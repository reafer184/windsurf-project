import { Router } from 'express';
import { requireAuth } from '../../middleware/auth.middleware.js';
import { validateBody } from '../../middleware/validate.js';
import { asyncHandler } from '../../middleware/async-handler.js';
import * as controller from './accounts.controller.js';
import { createAccountSchema, reorderSchema, updateAccountSchema } from './accounts.schemas.js';

export const accountsRouter = Router();

accountsRouter.use(requireAuth);

accountsRouter.get('/', asyncHandler(controller.list));
accountsRouter.post('/', validateBody(createAccountSchema), asyncHandler(controller.create));
accountsRouter.put('/reorder', validateBody(reorderSchema), asyncHandler(controller.reorder));
accountsRouter.put('/:id', validateBody(updateAccountSchema), asyncHandler(controller.update));
accountsRouter.delete('/:id', asyncHandler(controller.remove));
