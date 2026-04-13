import { z } from 'zod';

export const createAccountSchema = z.object({
  issuer: z.string().min(1).max(100),
  account_name: z.string().max(255).optional(),
  secret_enc: z.string().min(1),
  iv: z.string().min(1),
  digits: z.union([z.literal(6), z.literal(8)]).default(6),
  period: z.union([z.literal(30), z.literal(60)]).default(30),
  algorithm: z.enum(['SHA1', 'SHA256', 'SHA512']).default('SHA1')
});

export const updateAccountSchema = createAccountSchema.partial();

export const reorderSchema = z.object({
  ids: z.array(z.string().uuid()).min(1)
});
