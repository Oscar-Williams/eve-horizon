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

function render(services: Record<string, unknown>) {
  const deployer = new DeployerService(null as any, null as any);
  (deployer as any).logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
  // A role: worker service is deployed when the environment lists it.
  const environments = { prod: { workers: [{ service: 'worker' }] } };
  return (deployer as any).renderManifest({ manifestYaml: yaml.stringify({ services, environments }), ...params });
}

async function ingressHosts(services: Record<string, unknown>): Promise<string[]> {
  const result = await render(services);
  return yaml.parseAllDocuments(result.manifestYaml)
    .map((doc: any) => doc.toJSON())
    .filter((doc: any) => doc?.kind === 'Ingress')
    .map((doc: any) => doc.spec.rules[0].host);
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profile = 'legacy';
  mocks.decide.mockImplementation(async () => mocks.profile);
});

describe('DeployerService: services with ports and no x-eve.ingress block', () => {
  it('get no ingress under strict', async () => {
    mocks.profile = 'strict';

    expect(await ingressHosts({ web: { image: 'web:1', ports: ['3000'] } })).toEqual([]);
    expect(mocks.decide).toHaveBeenCalledWith(null, 'ports.implicit_public', expect.objectContaining({
      projectId: 'proj_shop',
      governing: 'project',
      detail: expect.objectContaining({ service: 'web', env: 'prod' }),
    }));
  });

  it('get a public ingress under audit, with a finding per service', async () => {
    mocks.profile = 'audit';

    const hosts = await ingressHosts({
      web: { image: 'web:1', ports: ['3000'] },
      worker: { image: 'worker:1', ports: ['9000'], 'x-eve': { role: 'worker' } },
    });

    expect(hosts.sort()).toEqual(['web.acme-shop-prod.apps.test', 'worker.acme-shop-prod.apps.test']);
    expect(mocks.decide.mock.calls.map((call) => call[2].detail.service).sort()).toEqual(['web', 'worker']);
  });

  it('keep a declared public ingress under strict, deciding nothing', async () => {
    mocks.profile = 'strict';

    const hosts = await ingressHosts({
      web: { image: 'web:1', ports: ['3000'], 'x-eve': { ingress: { public: true, port: 3000 } } },
      api: { image: 'api:1', ports: ['8080'], 'x-eve': { ingress: { port: 8080 } } },
    });

    expect(hosts).toEqual(['web.acme-shop-prod.apps.test']);
    expect(mocks.decide).not.toHaveBeenCalled();
  });
});
