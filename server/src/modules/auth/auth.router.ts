import { Router } from 'express';
import { validateBody } from '../../middleware/validate.js';
import { authRateLimit } from '../../middleware/rate-limit.js';
import { requireAuth } from '../../middleware/auth.middleware.js';
import * as controller from './auth.controller.js';
import {
  changePasswordSchema,
  loginSchema,
  refreshSchema,
  registerSchema,
  updateProfileSchema
} from './auth.schemas.js';

export const authRouter = Router();

authRouter.post('/register', authRateLimit, validateBody(registerSchema), controller.register);
authRouter.post('/login', authRateLimit, validateBody(loginSchema), controller.login);
authRouter.post('/refresh', validateBody(refreshSchema), controller.refresh);
authRouter.post('/logout', requireAuth, controller.logout);
authRouter.get('/me', requireAuth, controller.me);
authRouter.put('/me', requireAuth, validateBody(updateProfileSchema), controller.updateMe);
authRouter.post('/change-password', requireAuth, validateBody(changePasswordSchema), controller.changePassword);
