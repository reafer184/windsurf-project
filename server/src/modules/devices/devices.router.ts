import { Router } from 'express';
import { requireAuth } from '../../middleware/auth.middleware.js';
import * as controller from './devices.controller.js';

export const devicesRouter = Router();

devicesRouter.use(requireAuth);

devicesRouter.get('/', controller.list);
devicesRouter.delete('/:id', controller.remove);
devicesRouter.delete('/', controller.removeAll);
