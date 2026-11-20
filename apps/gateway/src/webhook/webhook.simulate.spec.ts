import { createHash } from 'node:crypto';
import { readFileSync } from 'fs';
import { resolve } from 'path';
import { NotFoundException, UnauthorizedException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { WebhookController } from './webhook.controller.js';

const api = vi.hoisted(() => ({ postJson: vi.fn() }));
vi.mock('../api-client.js', () => ({ postJson: api.postJson, getJson: vi.fn() }));
import type { GatewayChatService } from '../chat/gateway-chat.service.js';
import type { GatewayProviderRegistry } from '../providers/provider-registry.js';

const INTERNAL_KEY = 'internal-key';

function simulateRequest(headers: Record<string, string> = {}) {
  return {
    headers,
    body: {
      provider: 'slack',
      account_id: 'T_TEAM',
      user_id: 'U_SENDER',
      channel_id: 'C_CHAN',
      text: 'mission-control status',
      external_email: 'member@example.com',
    },
  };
}

describe('WebhookController simulate endpoint', () => {
  const resolveAndRoute = vi.fn();
  const controller = new WebhookController(
    {} as GatewayProviderRegistry,
    { resolveAndRoute } as unknown as GatewayChatService,
  );

  beforeEach(() => {
    api.postJson.mockReset();
    api.postJson.mockResolvedValue({ profile: 'audit' });
    resolveAndRoute.mockReset();
    resolveAndRoute.mockResolvedValue({});
    vi.stubEnv('EVE_INTERNAL_API_KEY', INTERNAL_KEY);
    vi.stubEnv('EVE_SIMULATE_ENABLED', 'true');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('refuses when simulate is turned off, even with the internal token', async () => {
    vi.stubEnv('EVE_SIMULATE_ENABLED', 'false');

    await expect(
      controller.handleSimulate(simulateRequest({ 'x-eve-internal-token': INTERNAL_KEY })),
    ).rejects.toThrow(NotFoundException);
    expect(resolveAndRoute).not.toHaveBeenCalled();
  });

  it('refuses a request without the internal token when simulate is on', async () => {
    await expect(controller.handleSimulate(simulateRequest())).rejects.toThrow(
      UnauthorizedException,
    );
    expect(resolveAndRoute).not.toHaveBeenCalled();
  });

  it('refuses a wrong internal token', async () => {
    await expect(
      controller.handleSimulate(simulateRequest({ 'x-eve-internal-token': 'internal-kez' })),
    ).rejects.toThrow(UnauthorizedException);
    expect(resolveAndRoute).not.toHaveBeenCalled();
  });

  it('refuses everything when no internal key is configured', async () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');

    await expect(
      controller.handleSimulate(simulateRequest({ 'x-eve-internal-token': '' })),
    ).rejects.toThrow(UnauthorizedException);
    expect(resolveAndRoute).not.toHaveBeenCalled();
  });

  it('routes the message with the internal token when simulate is on', async () => {
    await expect(
      controller.handleSimulate(simulateRequest({ 'x-eve-internal-token': INTERNAL_KEY })),
    ).resolves.toEqual({ immediate_reply: null, duplicate: false, route: null });

    expect(resolveAndRoute).toHaveBeenCalledWith(
      expect.objectContaining({
        accountId: 'T_TEAM',
        externalUserId: 'U_SENDER',
        externalEmail: 'member@example.com',
      }),
    );
  });

  it('takes the deliver key, refuses the core key alone, and judges only the legacy key beside it', async () => {
    const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
    vi.stubEnv('EVE_INTERNAL_CALLER_HASHES', `core:${sha('core-key-0123')},deliver:${sha('deliver-key-0123')}`);

    await expect(
      controller.handleSimulate(simulateRequest({ 'x-eve-service-key': 'core.core-key-0123' })),
    ).rejects.toThrow(UnauthorizedException);
    expect(resolveAndRoute).not.toHaveBeenCalled();

    // A previous release's API sends its core key and the legacy key: the core
    // key is ignored and the call is judged on the legacy key (one release).
    await expect(
      controller.handleSimulate(simulateRequest({ 'x-eve-service-key': 'core.core-key-0123', 'x-eve-internal-token': INTERNAL_KEY })),
    ).resolves.toBeDefined();

    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    await expect(
      controller.handleSimulate(simulateRequest({ 'x-eve-service-key': 'deliver.deliver-key-0123' })),
    ).resolves.toEqual({ immediate_reply: null, duplicate: false, route: null });
  });
});

describe('WebhookController simulate with only the legacy key (internal.service_key)', () => {
  const resolveAndRoute = vi.fn();

  beforeEach(() => {
    api.postJson.mockReset();
    resolveAndRoute.mockReset();
    resolveAndRoute.mockResolvedValue({});
    vi.stubEnv('EVE_INTERNAL_API_KEY', INTERNAL_KEY);
    vi.stubEnv('EVE_SIMULATE_ENABLED', 'true');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('is refused under strict, as the API decides', async () => {
    api.postJson.mockResolvedValue({ profile: 'strict' });
    const controller = new WebhookController(
      {} as GatewayProviderRegistry,
      { resolveAndRoute } as unknown as GatewayChatService,
    );
    await expect(
      controller.handleSimulate(simulateRequest({ 'x-eve-internal-token': INTERNAL_KEY })),
    ).rejects.toThrow(UnauthorizedException);
    expect(api.postJson).toHaveBeenCalledWith('/internal/security/legacy-key-calls', { route: '/gateway/providers/simulate' });
    expect(resolveAndRoute).not.toHaveBeenCalled();
  });
});

describe('gateway base manifest', () => {
  it('ships with simulate turned off', () => {
    const manifest = readFileSync(
      resolve(__dirname, '../../../../k8s/base/gateway-deployment.yaml'),
      'utf8',
    );
    const match = manifest.match(/-\s+name:\s+EVE_SIMULATE_ENABLED\s*\n\s+value:\s+"?([^"\n]*)"?/);
    const value = match?.[1]?.trim().toLowerCase();
    expect(value === undefined || value === 'false').toBe(true);
  });
});
