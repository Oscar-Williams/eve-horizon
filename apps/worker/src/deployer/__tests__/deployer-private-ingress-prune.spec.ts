import { beforeEach, describe, expect, it, vi } from 'vitest';
import yaml from 'yaml';
import { DeployerService } from '../deployer.service.js';

const mocks = vi.hoisted(() => ({
  profile: 'legacy' as 'legacy' | 'audit' | 'strict',
  decide: vi.fn(),
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: mocks.decide,
}));

vi.mock('@eve/shared', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    loadConfig: () => ({
      EVE_API_URL: 'http://api.eve.test',
      EVE_DEFAULT_DOMAIN: 'apps.test',
      EVE_DEFAULT_INGRESS_CLASS: 'nginx',
      EVE_DEFAULT_INGRESS_TIMEOUT: '300s',
      EVE_DEFAULT_INGRESS_MAX_BODY_SIZE: '10m',
      EVE_TCP_INGRESS_PROVIDER: 'none',
      EVE_COMPUTE_MODEL: 'k3s',
    }),
    resolveProjectSecrets: vi.fn().mockResolvedValue({ resolved: true, secrets: [], error: null }),
    mintServiceToken: vi.fn().mockResolvedValue('service-token'),
  };
});

const params = {
  namespace: 'eve-acme-shop-prod',
  envId: 'env_prod',
  envName: 'prod',
  projectSlug: 'shop',
  projectId: 'proj_shop',
  orgId: 'org_acme',
  orgSlug: 'acme',
  releaseId: 'rel_1',
};

function deployer(k8sService: unknown = null): DeployerService {
  const service = new DeployerService(null as any, k8sService as any);
  (service as any).logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
  return service;
}

async function privateIngresses(services: Record<string, unknown>): Promise<Array<{ name: string; component: string }>> {
  const result = await (deployer() as any).renderManifest({ manifestYaml: yaml.stringify({ services }), ...params });
  return result.privateServiceIngresses;
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profile = 'legacy';
  mocks.decide.mockImplementation(async () => mocks.profile);
});

describe('DeployerService: the Ingress of a service that is not public', () => {
  it('is named for removal when x-eve.ingress does not say public: true, on every profile', async () => {
    const names = await privateIngresses({
      web: { image: 'web:1', ports: ['3000'], 'x-eve': { ingress: { public: true, port: 3000 } } },
      api: { image: 'api:1', ports: ['8080'], 'x-eve': { ingress: { public: false, port: 8080 } } },
    });

    expect(names).toEqual([{ name: 'prod-api', component: 'api' }]);
  });

  it('is named for removal for a service with ports and no ingress block under strict', async () => {
    mocks.profile = 'strict';

    expect(await privateIngresses({ web: { image: 'web:1', ports: ['3000'] } })).toEqual([{ name: 'prod-web', component: 'web' }]);
  });

  it('is not named for a service with ports and no ingress block under audit, which stays public', async () => {
    mocks.profile = 'audit';

    expect(await privateIngresses({ web: { image: 'web:1', ports: ['3000'] } })).toEqual([]);
  });

  it("is removed only when Eve made it for that service and environment", async () => {
    const k8s = {
      listServiceIngresses: vi.fn(async () => [
        { name: 'prod-api', labels: { 'eve.component': 'api', 'eve.env_id': 'env_prod', 'eve.project_id': 'proj_shop' } },
        { name: 'prod-api-extra', labels: { 'eve.component': 'api', 'eve.env_id': 'env_prod', 'eve.project_id': 'proj_shop' } },
        { name: 'prod-web', labels: { 'eve.component': 'web', 'eve.env_id': 'env_prod', 'eve.project_id': 'proj_shop' } },
      ]),
      deleteIngress: vi.fn(async () => undefined),
    };

    await (deployer(k8s) as any).garbageCollectPrivateServiceIngresses(
      'eve-acme-shop-prod',
      [{ name: 'prod-api', component: 'api' }],
      { projectId: 'proj_shop', envId: 'env_prod' },
    );

    const selector = (k8s.listServiceIngresses.mock.calls[0] as unknown[])[1] as string;
    expect(selector.split(',').sort()).toEqual([
      '!eve.custom_domain',
      '!eve.ingress_alias',
      'eve.env_id=env_prod',
      'eve.project_id=proj_shop',
    ]);
    expect(k8s.deleteIngress).toHaveBeenCalledTimes(1);
    expect(k8s.deleteIngress).toHaveBeenCalledWith('eve-acme-shop-prod', 'prod-api');
  });

  it('lists nothing when no service needs its Ingress removed', async () => {
    const k8s = { listServiceIngresses: vi.fn(async () => []), deleteIngress: vi.fn() };

    await (deployer(k8s) as any).garbageCollectPrivateServiceIngresses('eve-acme-shop-prod', [], { projectId: 'proj_shop', envId: 'env_prod' });

    expect(k8s.listServiceIngresses).not.toHaveBeenCalled();
  });
});
