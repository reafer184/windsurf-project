import { prisma } from '../../config/database.js';

export const listDevices = async (userId: string) => {
  const devices = await prisma.refreshToken.findMany({
    where: {
      userId,
      revokedAt: null,
      expiresAt: { gt: new Date() }
    },
    orderBy: { createdAt: 'desc' }
  });

  return devices.map((device: { id: string; deviceName: string | null; createdAt: Date; expiresAt: Date }) => ({
    id: device.id,
    device_name: device.deviceName,
    created_at: device.createdAt,
    expires_at: device.expiresAt
  }));
};

export const revokeDevice = async (userId: string, id: string) => {
  await prisma.refreshToken.updateMany({
    where: { id, userId, revokedAt: null },
    data: { revokedAt: new Date() }
  });
};

export const revokeAllDevices = async (userId: string) => {
  await prisma.refreshToken.updateMany({
    where: { userId, revokedAt: null },
    data: { revokedAt: new Date() }
  });
};
