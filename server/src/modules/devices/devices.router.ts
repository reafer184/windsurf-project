import { Router } from 'express';
import { requireAuth } from '../../middleware/auth.middleware.js';
import { asyncHandler } from '../../middleware/async-handler.js';
import * as controller from './devices.controller.js';

export const devicesRouter = Router();

devicesRouter.use(requireAuth);

devicesRouter.get('/', asyncHandler(controller.list));
devicesRouter.delete('/:id', asyncHandler(controller.remove));
devicesRouter.delete('/', asyncHandler(controller.removeAll));
