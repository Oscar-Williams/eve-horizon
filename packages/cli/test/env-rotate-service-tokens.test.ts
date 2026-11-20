import { afterEach, describe, expect, it, vi } from 'vitest';
import { handleEnv } from '../src/commands/env';

vi.mock('../src/lib/client', () => ({
  requestJson: vi.fn(),
}));

import { requestJson } from '../src/lib/client';

const context = {
  apiUrl: 'http://example.test',
  token: 'token',
  profile: null,
  profileName: null,
  projectId: 'proj_shop',
};

describe('eve env rotate-service-tokens', () => {
  afterEach(() => {
    vi.mocked(requestJson).mockReset();
    vi.restoreAllMocks();
  });

  it('revokes the environment\'s service tokens and reports what was renewed', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce({
      id: 'env_prod',
      name: 'prod',
      service_tokens_not_before: '2026-11-20T12:00:00.000Z',
      renewal: 'done',
      renewed: [{ secret: 'prod-api-eve-secrets', key: 'EVE_SERVICE_TOKEN', reason: 'revoked' }],
    });
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});

    await handleEnv('rotate-service-tokens', ['prod'], {}, context as never);

    expect(requestJson).toHaveBeenCalledWith(
      context,
      '/projects/proj_shop/envs/prod/rotate-service-tokens',
      { method: 'POST', body: {} },
    );
    expect(log.mock.calls.flat().join('\n')).toContain('prod-api-eve-secrets');
  });

  it('takes the project from --project', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce({
      id: 'env_prod', name: 'prod', service_tokens_not_before: '2026-11-20T12:00:00.000Z', renewal: 'scheduled', renewed: [],
    });
    vi.spyOn(console, 'log').mockImplementation(() => {});

    await handleEnv('rotate-service-tokens', ['prod'], { project: 'proj_ledger' }, context as never);

    expect(requestJson).toHaveBeenCalledWith(
      context,
      '/projects/proj_ledger/envs/prod/rotate-service-tokens',
      { method: 'POST', body: {} },
    );
  });

  it('says what was renewed, what waits for the hourly renewal and what failed', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce({
      id: 'env_prod',
      name: 'prod',
      service_tokens_not_before: '2026-11-20T12:00:00.000Z',
      renewal: 'incomplete',
      counts: { renewed: 1, conflicted: 1, failed: 1 },
      renewed: [{ secret: 'prod-api-eve-secrets', key: 'EVE_SERVICE_TOKEN', reason: 'revoked' }],
      conflicted: [{ secret: 'prod-web-eve-secrets', key: 'EVE_SERVICE_TOKEN', reason: 'revoked' }],
      failed: [{ secret: 'prod-worker-eve-secrets', key: 'EVE_SERVICE_TOKEN', reason: 'revoked' }],
    });
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});

    await handleEnv('rotate-service-tokens', ['prod'], {}, context as never);

    const out = log.mock.calls.flat().join('\n');
    expect(out).toMatch(/1 renewed, 1 changed by a deploy, 1 failed/);
    expect(out).toContain('prod-web-eve-secrets');
    expect(out).toContain('prod-worker-eve-secrets');
    expect(out).toMatch(/hourly renewal/);
  });
});
