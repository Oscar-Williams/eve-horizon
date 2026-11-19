import { createHash } from 'node:crypto';
import { UnauthorizedException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeliveryController } from './delivery.controller.js';

const CORE = 'core-key-0123456789';
const GATEWAY = 'gateway-key-0123456789';
const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

describe('DeliveryController internal keys', () => {
  const getInstance = vi.fn().mockReturnValue(undefined);
  const controller = new DeliveryController({ getInstance } as any);
  const body = { provider: 'slack', account_id: 'acct', channel_id: 'chan', text: 'hi' };

  beforeEach(() => {
    getInstance.mockClear();
    vi.stubEnv('EVE_INTERNAL_API_KEY', 'internal-key');
    // The gateway holds its own key and only the hash of the core key.
    vi.stubEnv('EVE_INTERNAL_GATEWAY_KEY', GATEWAY);
    vi.stubEnv('EVE_INTERNAL_CALLER_HASHES', `core:${sha(CORE)},gateway:${sha(GATEWAY)}`);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('refuses a missing or wrong token', async () => {
    await expect(controller.handleDelivery({}, body)).rejects.toThrow(UnauthorizedException);
    await expect(controller.handleDelivery({ 'x-eve-internal-token': 'internal-kez' }, body)).rejects.toThrow(UnauthorizedException);
    expect(getInstance).not.toHaveBeenCalled();
  });

  it('refuses everything when no key is configured', async () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    vi.stubEnv('EVE_INTERNAL_CALLER_HASHES', '');
    await expect(controller.handleDelivery({ 'x-eve-internal-token': '' }, body)).rejects.toThrow(UnauthorizedException);
    await expect(controller.handleDelivery({ 'x-eve-service-key': `core.${CORE}` }, body)).rejects.toThrow(UnauthorizedException);
  });

  it('accepts the legacy key while it is configured', async () => {
    await expect(controller.handleDelivery({ 'x-eve-internal-token': 'internal-key' }, body)).resolves.toEqual({
      delivered: false,
      reason: 'no_provider_instance',
    });
  });

  it('accepts the core key, verified by its hash', async () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    await expect(controller.handleDelivery({ 'x-eve-service-key': `core.${CORE}` }, body)).resolves.toMatchObject({
      delivered: false,
    });
  });

  it('refuses its own key and the SSO key: only core services deliver', async () => {
    await expect(
      controller.handleDelivery({ 'x-eve-service-key': `gateway.${GATEWAY}`, 'x-eve-internal-token': 'internal-key' }, body),
    ).rejects.toThrow(UnauthorizedException);
    expect(getInstance).not.toHaveBeenCalled();
  });
});
