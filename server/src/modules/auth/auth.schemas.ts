import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  display_name: z.string().min(1).max(100).optional()
});

export const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  device_name: z.string().max(100).optional()
});

export const refreshSchema = z.object({
  refresh_token: z.string().min(1),
  device_name: z.string().max(100).optional()
});

export const updateProfileSchema = z.object({
  display_name: z.string().min(1).max(100)
});

export const changePasswordSchema = z.object({
  current_password: z.string().min(8),
  new_password: z.string().min(8)
});
