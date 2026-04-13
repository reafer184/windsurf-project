import type { Request, Response } from 'express';
import * as authService from './auth.service.js';
import { writeAuditLog } from '../../utils/audit.js';

export const register = async (req: Request, res: Response): Promise<void> => {
  const data = await authService.register(req.body);
  await writeAuditLog(req, 'register', data.user.id);
  res.status(201).json(data);
};

export const login = async (req: Request, res: Response): Promise<void> => {
  const data = await authService.login(req.body);
  await writeAuditLog(req, 'login');
  res.status(200).json(data);
};

export const refresh = async (req: Request, res: Response): Promise<void> => {
  const data = await authService.refresh(req.body);
  res.status(200).json(data);
};

export const logout = async (req: Request, res: Response): Promise<void> => {
  await authService.logout(req.body?.refresh_token);
  if (req.user) {
    await writeAuditLog(req, 'logout', req.user.sub);
  }
  res.status(200).json({ ok: true });
};

export const me = async (req: Request, res: Response): Promise<void> => {
  const data = await authService.getMe(req.user!.sub);
  res.status(200).json({ user: data });
};

export const updateMe = async (req: Request, res: Response): Promise<void> => {
  const data = await authService.updateMe(req.user!.sub, req.body.display_name);
  res.status(200).json({ user: data });
};

export const changePassword = async (req: Request, res: Response): Promise<void> => {
  await authService.changePassword(req.user!.sub, req.body.current_password, req.body.new_password);
  res.status(200).json({ ok: true });
};
