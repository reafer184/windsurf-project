import type { Request, Response } from 'express';
import * as accountsService from './accounts.service.js';
import { writeAuditLog } from '../../utils/audit.js';

export const list = async (req: Request, res: Response): Promise<void> => {
  const accounts = await accountsService.listAccounts(req.user!.sub);
  res.status(200).json({ accounts });
};

export const create = async (req: Request, res: Response): Promise<void> => {
  const account = await accountsService.createAccount(req.user!.sub, req.body);
  await writeAuditLog(req, 'add_account', req.user!.sub, { accountId: account.id, issuer: account.issuer });
  res.status(201).json({ account });
};

export const update = async (req: Request, res: Response): Promise<void> => {
  const account = await accountsService.updateAccount(req.user!.sub, req.params.id, req.body);
  res.status(200).json({ account });
};

export const remove = async (req: Request, res: Response): Promise<void> => {
  await accountsService.deleteAccount(req.user!.sub, req.params.id);
  await writeAuditLog(req, 'delete_account', req.user!.sub, { accountId: req.params.id });
  res.status(200).json({ ok: true });
};

export const reorder = async (req: Request, res: Response): Promise<void> => {
  await accountsService.reorderAccounts(req.user!.sub, req.body.ids);
  res.status(200).json({ ok: true });
};
