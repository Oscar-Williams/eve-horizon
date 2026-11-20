import { BadRequestException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { describe, expect, it, vi } from 'vitest';
import { INTERNAL_CALLERS_KEY } from '../common/internal-token.guard.js';
import { SecurityInternalController } from './security.internal.controller.js';
import type { SecurityService } from './security.service.js';

/**
 * The gateway holds no database, so it asks the API how to treat a call
 * that only the legacy internal key proved: the API decides
 * `internal.service_key` for the instance and records the finding, as the
 * worker and agent runtime do for their own calls.
 */
describe('SecurityInternalController legacy-key calls', () => {
  it('decides internal.service_key for the instance and records the call the gateway received', async () => {
    const decide = vi.fn(async () => 'strict');
    const controller = new SecurityInternalController({ decide } as unknown as SecurityService);

    await expect(controller.legacyKeyCall({ route: '/internal/deliver' })).resolves.toEqual({ profile: 'strict' });
    expect(decide).toHaveBeenCalledWith('internal.service_key', {
      governing: 'instance',
      principal: { type: 'service', id: 'legacy-key' },
      detail: { caller: 'legacy-key', callee: 'gateway', route: '/internal/deliver' },
    });
  });

  it('keeps the recorded route short, and needs one', async () => {
    const decide = vi.fn(async () => 'audit');
    const controller = new SecurityInternalController({ decide } as unknown as SecurityService);

    await controller.legacyKeyCall({ route: `/internal/${'x'.repeat(300)}` });
    const detail = (decide.mock.calls[0] as unknown as [string, { detail: { route: string } }])[1].detail;
    expect(detail.route.length).toBe(120);
    await expect(controller.legacyKeyCall({} as never)).rejects.toThrow(BadRequestException);
  });

  it('is a gateway route', () => {
    const callers = new Reflector().getAllAndOverride<string[]>(INTERNAL_CALLERS_KEY, [
      SecurityInternalController.prototype.legacyKeyCall,
      SecurityInternalController,
    ]);
    expect(callers).toEqual(['gateway']);
  });
});
