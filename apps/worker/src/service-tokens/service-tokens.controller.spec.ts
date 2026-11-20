import { BadRequestException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { ServiceTokensController } from './service-tokens.controller.js';
import type { ServiceTokenRenewalService } from './service-token-renewal.service.js';

/** The API's rotate route asks the worker to renew one environment's tokens at once. */
describe('POST /service-tokens/renew', () => {
  it('renews the named environment only, and says what it renewed, what was held back and what failed', async () => {
    const entry = (secret: string) =>
      ({ env_id: 'env_prod', namespace: 'eve-acme-shop-prod', secret, key: 'EVE_SERVICE_TOKEN', reason: 'revoked' as const });
    const report = { renewed: [entry('prod-api-eve-secrets')], conflicted: [entry('prod-web-eve-secrets')], failed: [] };
    const renewal = { renewEnvironment: vi.fn(async () => report), renewAll: vi.fn() };
    const controller = new ServiceTokensController(renewal as unknown as ServiceTokenRenewalService);

    expect(await controller.renew({ env_id: 'env_prod' })).toEqual(report);
    expect(renewal.renewEnvironment).toHaveBeenCalledWith('env_prod');
    expect(renewal.renewAll).not.toHaveBeenCalled();
  });

  it('needs env_id', async () => {
    const controller = new ServiceTokensController({ renewEnvironment: vi.fn() } as unknown as ServiceTokenRenewalService);
    await expect(controller.renew({})).rejects.toThrow(BadRequestException);
  });
});
