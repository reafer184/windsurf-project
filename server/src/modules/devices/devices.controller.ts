import type { Request, Response } from 'express';
import * as service from './devices.service.js';

export const list = async (req: Request, res: Response): Promise<void> => {
  const devices = await service.listDevices(req.user!.sub);
  res.status(200).json({ devices });
};

export const remove = async (req: Request, res: Response): Promise<void> => {
  await service.revokeDevice(req.user!.sub, req.params.id);
  res.status(200).json({ ok: true });
};

export const removeAll = async (req: Request, res: Response): Promise<void> => {
  await service.revokeAllDevices(req.user!.sub);
  res.status(200).json({ ok: true });
};
