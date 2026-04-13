import { Router } from 'express';
import { requireAuth } from '../../middleware/auth.middleware.js';
import { validateBody } from '../../middleware/validate.js';
import * as controller from './accounts.controller.js';
import { createAccountSchema, reorderSchema, updateAccountSchema } from './accounts.schemas.js';

export const accountsRouter = Router();

accountsRouter.use(requireAuth);

accountsRouter.get('/', controller.list);
accountsRouter.post('/', validateBody(createAccountSchema), controller.create);
accountsRouter.put('/reorder', validateBody(reorderSchema), controller.reorder);
accountsRouter.put('/:id', validateBody(updateAccountSchema), controller.update);
accountsRouter.delete('/:id', controller.remove);
