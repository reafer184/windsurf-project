import type { Request } from 'express';
import { prisma } from '../config/database.js';

export const writeAuditLog = async (
  req: Request,
  action: string,
  userId?: string,
  metadata?: Record<string, unknown>
): Promise<void> => {
  try {
    await prisma.auditLog.create({
      data: {
        userId,
        action,
        ipAddress: req.ip,
        userAgent: req.headers['user-agent'] ?? null,
        metadata: metadata ? (metadata as any) : undefined
      }
    });
  } catch (error) {
    console.error('Audit log write failed:', error);
  }
};
