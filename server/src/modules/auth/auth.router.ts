import { Router } from 'express';
import { validateBody } from '../../middleware/validate.js';
import { authRateLimit } from '../../middleware/rate-limit.js';
import { requireAuth } from '../../middleware/auth.middleware.js';
import { asyncHandler } from '../../middleware/async-handler.js';
import * as controller from './auth.controller.js';
import {
  changePasswordSchema,
  loginSchema,
  refreshSchema,
  registerSchema,
  updateProfileSchema
} from './auth.schemas.js';

export const authRouter = Router();

authRouter.post('/register', authRateLimit, validateBody(registerSchema), asyncHandler(controller.register));
authRouter.post('/login', authRateLimit, validateBody(loginSchema), asyncHandler(controller.login));
authRouter.post('/refresh', validateBody(refreshSchema), asyncHandler(controller.refresh));
authRouter.post('/logout', requireAuth, asyncHandler(controller.logout));
authRouter.get('/me', requireAuth, asyncHandler(controller.me));
authRouter.put('/me', requireAuth, validateBody(updateProfileSchema), asyncHandler(controller.updateMe));
authRouter.post('/change-password', requireAuth, validateBody(changePasswordSchema), asyncHandler(controller.changePassword));
