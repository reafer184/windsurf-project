import { prisma } from '../../config/database.js';
import { HttpError } from '../../utils/http-error.js';
import type { TotpAccount } from '@prisma/client';

interface CreateAccountInput {
  issuer: string;
  account_name?: string;
  secret_enc: string;
  iv: string;
  digits?: 6 | 8;
  period?: 30 | 60;
  algorithm?: 'SHA1' | 'SHA256' | 'SHA512';
}

interface UpdateAccountInput extends Partial<CreateAccountInput> {}

export const listAccounts = async (userId: string) => {
  const accounts = await prisma.totpAccount.findMany({
    where: { userId },
    orderBy: [{ sortOrder: 'asc' }, { createdAt: 'desc' }]
  });

  return accounts.map((item: TotpAccount) => ({
    id: item.id,
    issuer: item.issuer,
    account_name: item.accountName,
    secret_enc: item.secretEnc,
    iv: item.iv,
    digits: item.digits,
    period: item.period,
    algorithm: item.algorithm,
    sort_order: item.sortOrder,
    created_at: item.createdAt,
    updated_at: item.updatedAt
  }));
};

export const createAccount = async (userId: string, input: CreateAccountInput) => {
  const max = await prisma.totpAccount.aggregate({
    where: { userId },
    _max: { sortOrder: true }
  });

  const account = await prisma.totpAccount.create({
    data: {
      userId,
      issuer: input.issuer,
      accountName: input.account_name,
      secretEnc: input.secret_enc,
      iv: input.iv,
      digits: input.digits ?? 6,
      period: input.period ?? 30,
      algorithm: input.algorithm ?? 'SHA1',
      sortOrder: (max._max.sortOrder ?? -1) + 1
    }
  });

  return account;
};

export const updateAccount = async (userId: string, accountId: string, input: UpdateAccountInput) => {
  const existing = await prisma.totpAccount.findFirst({ where: { id: accountId, userId } });

  if (!existing) {
    throw new HttpError(404, 'NOT_FOUND', 'Аккаунт не найден');
  }

  const updated = await prisma.totpAccount.update({
    where: { id: accountId },
    data: {
      issuer: input.issuer,
      accountName: input.account_name,
      secretEnc: input.secret_enc,
      iv: input.iv,
      digits: input.digits,
      period: input.period,
      algorithm: input.algorithm
    }
  });

  return updated;
};

export const deleteAccount = async (userId: string, accountId: string) => {
  const existing = await prisma.totpAccount.findFirst({ where: { id: accountId, userId } });

  if (!existing) {
    throw new HttpError(404, 'NOT_FOUND', 'Аккаунт не найден');
  }

  await prisma.totpAccount.delete({ where: { id: accountId } });
};

export const reorderAccounts = async (userId: string, ids: string[]) => {
  const found = await prisma.totpAccount.findMany({
    where: { userId, id: { in: ids } },
    select: { id: true }
  });

  if (found.length !== ids.length) {
    throw new HttpError(403, 'FORBIDDEN', 'Нельзя менять порядок чужих аккаунтов');
  }

  await prisma.$transaction(
    ids.map((id, index) =>
      prisma.totpAccount.update({
        where: { id },
        data: { sortOrder: index }
      })
    )
  );
};
