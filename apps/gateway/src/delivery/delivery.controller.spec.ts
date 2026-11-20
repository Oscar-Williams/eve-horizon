import { createHash } from 'node:crypto';
import { UnauthorizedException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { DeliveryController } from './delivery.controller.js';

// The gateway has no database: it asks the API how to treat a legacy-key call.
const api = vi.hoisted(() => ({ postJson: vi.fn() }));
vi.mock('../api-client.js', () => ({ postJson: api.postJson, getJson: vi.fn() }));

const CORE = 'core-key-0123456789';
const GATEWAY = 'gateway-key-0123456789';
const DELIVER = 'deliver-key-0123456789';
const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

describe('DeliveryController internal keys', () => {
  const getInstance = vi.fn().mockReturnValue(undefined);
  const controller = new DeliveryController({ getInstance } as any);
  const body = { provider: 'slack', account_id: 'acct', channel_id: 'chan', text: 'hi' };

  beforeEach(() => {
    getInstance.mockClear();
    api.postJson.mockReset();
    api.postJson.mockResolvedValue({ profile: 'audit' });
    vi.stubEnv('EVE_INTERNAL_API_KEY', 'internal-key');
    // The gateway holds its own key and only hashes of the others, the
    // core key's included (the instance's one hash list).
    vi.stubEnv('EVE_INTERNAL_GATEWAY_KEY', GATEWAY);
    vi.stubEnv('EVE_INTERNAL_CALLER_HASHES', `core:${sha(CORE)},gateway:${sha(GATEWAY)},deliver:${sha(DELIVER)}`);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('refuses a missing or wrong token', async () => {
    await expect(controller.handleDelivery({}, body)).rejects.toThrow(UnauthorizedException);
    await expect(controller.handleDelivery({ 'x-eve-internal-token': 'internal-kez' }, body)).rejects.toThrow(UnauthorizedException);
    await expect(controller.handleDelivery({ 'x-eve-service-key': `deliver.${DELIVER}x` }, body)).rejects.toThrow(UnauthorizedException);
    expect(getInstance).not.toHaveBeenCalled();
  });

  it('refuses everything when no key is configured', async () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    vi.stubEnv('EVE_INTERNAL_CALLER_HASHES', '');
    await expect(controller.handleDelivery({ 'x-eve-internal-token': '' }, body)).rejects.toThrow(UnauthorizedException);
    await expect(controller.handleDelivery({ 'x-eve-service-key': `deliver.${DELIVER}` }, body)).rejects.toThrow(UnauthorizedException);
  });

  it('accepts the legacy key while it is configured', async () => {
    await expect(controller.handleDelivery({ 'x-eve-internal-token': 'internal-key' }, body)).resolves.toEqual({
      delivered: false,
      reason: 'no_provider_instance',
    });
  });

  it('accepts the deliver key, verified by its hash', async () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    await expect(controller.handleDelivery({ 'x-eve-service-key': `deliver.${DELIVER}` }, body)).resolves.toMatchObject({
      delivered: false,
    });
  });

  it('refuses the core key, even with its hash configured and the legacy key beside it', async () => {
    await expect(controller.handleDelivery({ 'x-eve-service-key': `core.${CORE}` }, body)).rejects.toThrow(UnauthorizedException);
    await expect(
      controller.handleDelivery({ 'x-eve-service-key': `core.${CORE}`, 'x-eve-internal-token': 'internal-key' }, body),
    ).rejects.toThrow(UnauthorizedException);
    expect(getInstance).not.toHaveBeenCalled();
  });

  it('refuses its own key and the SSO key: only the services that deliver', async () => {
    await expect(
      controller.handleDelivery({ 'x-eve-service-key': `gateway.${GATEWAY}`, 'x-eve-internal-token': 'internal-key' }, body),
    ).rejects.toThrow(UnauthorizedException);
    expect(getInstance).not.toHaveBeenCalled();
  });

  describe('a call with only the legacy key (internal.service_key)', () => {
    it('is refused under strict, as the API decides and records it', async () => {
      api.postJson.mockResolvedValue({ profile: 'strict' });
      const judged = new DeliveryController({ getInstance } as any);
      await expect(judged.handleDelivery({ 'x-eve-internal-token': 'internal-key' }, body)).rejects.toThrow(UnauthorizedException);
      expect(api.postJson).toHaveBeenCalledWith('/internal/security/legacy-key-calls', { route: '/internal/deliver' });
      expect(getInstance).not.toHaveBeenCalled();
    });

    it('passes under audit, once the API has recorded it', async () => {
      const judged = new DeliveryController({ getInstance } as any);
      await expect(judged.handleDelivery({ 'x-eve-internal-token': 'internal-key' }, body)).resolves.toMatchObject({ delivered: false });
      expect(api.postJson).toHaveBeenCalledWith('/internal/security/legacy-key-calls', { route: '/internal/deliver' });
    });

    it('is not asked about a deliver-key call', async () => {
      api.postJson.mockResolvedValue({ profile: 'strict' });
      const judged = new DeliveryController({ getInstance } as any);
      await expect(judged.handleDelivery({ 'x-eve-service-key': `deliver.${DELIVER}`, 'x-eve-internal-token': 'internal-key' }, body))
        .resolves.toMatchObject({ delivered: false });
      expect(api.postJson).not.toHaveBeenCalled();
    });
  });
});
