import { NotFoundException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { PERMISSION_KEY } from '../auth/permission.decorator';
import { EnvironmentsController } from './environments.controller';
import { EnvironmentsService } from './environments.service';

/**
 * `eve env rotate-service-tokens <env>` revokes the environment's service
 * tokens issued until now (service_tokens_not_before, whole seconds on the
 * API's clock) and asks the worker to renew that environment at once; the
 * worker's hourly renewal is the backstop.
 */

const NOW = Date.UTC(2026, 10, 20, 12, 0, 0, 750);

describe('rotate service tokens', () => {
  let service: EnvironmentsService;
  let environments: Record<string, ReturnType<typeof vi.fn>>;
  let fetchMock: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    process.env.WORKER_URL = 'http://worker.eve.example';
    delete process.env.EVE_WORKER_URLS;
    process.env.EVE_INTERNAL_API_KEY = 'core-key';
    environments = {
      findByProjectAndName: vi.fn(async (projectId: string, name: string) =>
        (projectId === 'proj_shop' && name === 'prod' ? { id: 'env_prod', project_id: 'proj_shop', name: 'prod' } : null)),
      revokeServiceTokens: vi.fn(async (id: string, notBefore: Date) =>
        ({ id, project_id: 'proj_shop', name: 'prod', service_tokens_not_before: notBefore })),
    };
    service = new EnvironmentsService(null as any, {} as any, {} as any, {} as any);
    Object.assign(service as any, { environments });
    fetchMock = vi.fn(async () => new Response(JSON.stringify({
      renewed: [{ env_id: 'env_prod', namespace: 'eve-acme-shop-prod', secret: 'prod-api-eve-secrets', key: 'EVE_SERVICE_TOKEN', reason: 'revoked' }],
    }), { status: 200, headers: { 'content-type': 'application/json' } }));
    vi.stubGlobal('fetch', fetchMock);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
    delete process.env.WORKER_URL;
  });

  it('needs envs:write', () => {
    const handler = EnvironmentsController.prototype.rotateServiceTokens;
    expect(handler).toBeTypeOf('function');
    expect(Reflect.getMetadata(PERMISSION_KEY, handler)).toEqual(['envs:write']);
  });

  it('sets the timestamp and renews that environment only', async () => {
    const result = await service.rotateServiceTokens('proj_shop', 'prod');

    const notBefore = new Date(Date.UTC(2026, 10, 20, 12, 0, 0));
    expect(environments.revokeServiceTokens).toHaveBeenCalledWith('env_prod', notBefore);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(url).toBe('http://worker.eve.example/service-tokens/renew');
    expect(init.method).toBe('POST');
    expect(JSON.parse(init.body as string)).toEqual({ env_id: 'env_prod' });
    expect(result).toEqual({
      id: 'env_prod',
      name: 'prod',
      service_tokens_not_before: notBefore.toISOString(),
      renewal: 'done',
      renewed: [{ secret: 'prod-api-eve-secrets', key: 'EVE_SERVICE_TOKEN', reason: 'revoked' }],
    });
  });

  it('still revokes when the worker cannot be reached; the hourly renewal follows', async () => {
    fetchMock.mockRejectedValueOnce(new Error('connect ECONNREFUSED'));

    const result = await service.rotateServiceTokens('proj_shop', 'prod');

    expect(environments.revokeServiceTokens).toHaveBeenCalledTimes(1);
    expect(result).toMatchObject({ renewal: 'scheduled', renewed: [] });
  });

  it('is not found for an unknown environment', async () => {
    await expect(service.rotateServiceTokens('proj_shop', 'staging')).rejects.toThrow(NotFoundException);
    expect(environments.revokeServiceTokens).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
