import bcrypt from 'bcrypt';
import { env } from '../config/env.js';

export const hashPassword = (password: string) => bcrypt.hash(password, env.BCRYPT_ROUNDS);

export const comparePassword = (password: string, hash: string) => bcrypt.compare(password, hash);
