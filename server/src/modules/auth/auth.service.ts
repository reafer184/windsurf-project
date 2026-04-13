import { prisma } from '../../config/database.js';
import { comparePassword, hashPassword } from '../../utils/bcrypt.js';
import { HttpError } from '../../utils/http-error.js';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../../utils/jwt.js';
import { sha256 } from '../../utils/hash.js';

interface RegisterInput {
  email: string;
  password: string;
  display_name?: string;
}

interface LoginInput {
  email: string;
  password: string;
  device_name?: string;
}

interface RefreshInput {
  refresh_token: string;
  device_name?: string;
}

export const register = async (input: RegisterInput) => {
  const existing = await prisma.user.findUnique({ where: { email: input.email } });

  if (existing) {
    throw new HttpError(409, 'EMAIL_TAKEN', 'Email уже зарегистрирован');
  }

  const passwordHash = await hashPassword(input.password);

  const user = await prisma.user.create({
    data: {
      email: input.email,
      passwordHash,
      displayName: input.display_name
    }
  });

  const payload = { sub: user.id, email: user.email };
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: sha256(refreshToken),
      deviceName: 'unknown',
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });

  return {
    user: {
      id: user.id,
      email: user.email,
      display_name: user.displayName
    },
    access_token: accessToken,
    refresh_token: refreshToken
  };
};

export const login = async (input: LoginInput) => {
  const user = await prisma.user.findUnique({ where: { email: input.email } });

  if (!user) {
    throw new HttpError(401, 'INVALID_CREDENTIALS', 'Неверный email или пароль');
  }

  const valid = await comparePassword(input.password, user.passwordHash);

  if (!valid) {
    throw new HttpError(401, 'INVALID_CREDENTIALS', 'Неверный email или пароль');
  }

  const payload = { sub: user.id, email: user.email };
  const accessToken = signAccessToken(payload);
  const refreshToken = signRefreshToken(payload);

  await prisma.refreshToken.create({
    data: {
      userId: user.id,
      tokenHash: sha256(refreshToken),
      deviceName: input.device_name ?? 'unknown',
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });

  return {
    access_token: accessToken,
    refresh_token: refreshToken,
    expires_in: 900
  };
};

export const refresh = async (input: RefreshInput) => {
  let payload: { sub: string; email: string };

  try {
    payload = verifyRefreshToken(input.refresh_token);
  } catch {
    throw new HttpError(401, 'UNAUTHORIZED', 'Невалидный refresh token');
  }

  const tokenHash = sha256(input.refresh_token);

  const current = await prisma.refreshToken.findUnique({
    where: { tokenHash }
  });

  if (!current || current.revokedAt || current.expiresAt <= new Date()) {
    throw new HttpError(401, 'UNAUTHORIZED', 'Refresh token истёк или отозван');
  }

  await prisma.refreshToken.update({
    where: { id: current.id },
    data: { revokedAt: new Date() }
  });

  const newAccessToken = signAccessToken({ sub: payload.sub, email: payload.email });
  const newRefreshToken = signRefreshToken({ sub: payload.sub, email: payload.email });

  await prisma.refreshToken.create({
    data: {
      userId: payload.sub,
      tokenHash: sha256(newRefreshToken),
      deviceName: input.device_name ?? current.deviceName ?? 'unknown',
      expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000)
    }
  });

  return {
    access_token: newAccessToken,
    refresh_token: newRefreshToken,
    expires_in: 900
  };
};

export const logout = async (refreshToken?: string) => {
  if (!refreshToken) {
    return;
  }

  const tokenHash = sha256(refreshToken);
  await prisma.refreshToken.updateMany({
    where: { tokenHash },
    data: { revokedAt: new Date() }
  });
};

export const getMe = async (userId: string) => {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    throw new HttpError(404, 'NOT_FOUND', 'Пользователь не найден');
  }

  return {
    id: user.id,
    email: user.email,
    display_name: user.displayName,
    is_verified: user.isVerified,
    created_at: user.createdAt
  };
};

export const updateMe = async (userId: string, displayName: string) => {
  const user = await prisma.user.update({
    where: { id: userId },
    data: { displayName }
  });

  return {
    id: user.id,
    email: user.email,
    display_name: user.displayName,
    is_verified: user.isVerified
  };
};

export const changePassword = async (userId: string, currentPassword: string, newPassword: string) => {
  const user = await prisma.user.findUnique({ where: { id: userId } });

  if (!user) {
    throw new HttpError(404, 'NOT_FOUND', 'Пользователь не найден');
  }

  const valid = await comparePassword(currentPassword, user.passwordHash);

  if (!valid) {
    throw new HttpError(401, 'INVALID_CREDENTIALS', 'Текущий пароль неверный');
  }

  const passwordHash = await hashPassword(newPassword);

  await prisma.user.update({
    where: { id: userId },
    data: { passwordHash }
  });
};
