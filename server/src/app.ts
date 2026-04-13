import express, { type Request, type Response } from 'express';
import helmet from 'helmet';
import cors from 'cors';
import { env } from './config/env.js';
import { authRouter } from './modules/auth/auth.router.js';
import { accountsRouter } from './modules/accounts/accounts.router.js';
import { devicesRouter } from './modules/devices/devices.router.js';
import { errorHandler } from './middleware/error-handler.js';

export const app = express();

app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({ origin: env.CORS_ORIGIN === '*' ? true : env.CORS_ORIGIN }));
app.use(express.json({ limit: '1mb' }));

app.get('/health', (_req: Request, res: Response) => {
  res.status(200).json({ ok: true });
});

app.use('/api/v1/auth', authRouter);
app.use('/api/v1/accounts', accountsRouter);
app.use('/api/v1/devices', devicesRouter);

app.use(errorHandler);
