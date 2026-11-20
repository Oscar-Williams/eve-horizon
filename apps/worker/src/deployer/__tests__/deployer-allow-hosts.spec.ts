import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DeployerService } from '../deployer.service.js';

// egress.allow_hosts at deploy: a strict project with no FQDN provider is
// refused before anything is written; with the GKE provider the env's
// policies are written from the release's manifest, before the workloads.

const mocks = vi.hoisted(() => ({
  profiles: {} as Record<string, 'legacy' | 'audit' | 'strict'>,
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: vi.fn(async (_db: unknown, rule: string) => mocks.profiles[rule] ?? 'legacy'),
  governingSecurityProfile: vi.fn(async (_db: unknown, ctx: { rule: string }) => mocks.profiles[ctx.rule] ?? 'legacy'),
}));

vi.mock('@eve/shared', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    loadConfig: () => ({
      EVE_API_URL: 'http://eve-api:4791',
      EVE_API_APP_URL: 'http://eve-api.eve.svc.cluster.local:4701',
      EVE_DEFAULT_DOMAIN: '',
      EVE_TCP_INGRESS_PROVIDER: 'none',
      EVE_COMPUTE_MODEL: 'k3s',
    }),
    resolveProjectSecrets: vi.fn(async () => ({ resolved: true, secrets: [], error: null })),
    mintServiceToken: vi.fn(async () => ({ access_token: 'svc-token' })),
  };
});

const MANIFEST = 'x-eve:\n  egress:\n    hosts: [api.example.com]\nservices: {}\n';

function deployerFor() {
  const order: string[] = [];
  const k8s = {
    createNamespace: vi.fn(async () => undefined),
    applyManifest: vi.fn(async () => { order.push('workloads'); }),
    listAliasIngresses: vi.fn(async () => []),
    listCustomDomainIngresses: vi.fn(async () => []),
    listSecrets: vi.fn(async () => []),
    deleteSecret: vi.fn(),
    deploymentExists: vi.fn(async () => false),
    getDeploymentStatus: vi.fn(async () => ({ ready: true, availableReplicas: 0, desiredReplicas: 0, conditions: [] })),
  };
  const deployer = new DeployerService(null as any, k8s as any);
  const egress = {
    applyEnv: vi.fn(async (_env: unknown, profile: string) => { order.push(`env:${profile}`); return { profile, applied: [], removed: [] }; }),
    applyRunners: vi.fn(async (_projectId: string, profile: string) => { order.push(`runners:${profile}`); return { profile, applied: [], removed: [] }; }),
  };
  Object.assign(deployer as any, {
    logger: { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() },
    egress,
    environments: {
      findById: vi.fn().mockResolvedValue({ id: 'env_prod', project_id: 'proj_shop', name: 'prod', namespace: null, overrides_json: null }),
    },
    releases: {
      findById: vi.fn().mockResolvedValue({ id: 'rel_1', project_id: 'proj_shop', manifest_hash: 'h', image_digests_json: null }),
    },
    projects: { findById: vi.fn().mockResolvedValue({ id: 'proj_shop', org_id: 'org_acme', slug: 'shop', repo_url: null }) },
    orgs: { findById: vi.fn().mockResolvedValue({ id: 'org_acme', slug: 'acme' }) },
    manifests: {
      findByProjectAndHash: vi.fn().mockResolvedValue({ id: 'man_1', manifest_yaml: MANIFEST }),
      markSynced: vi.fn(async () => { order.push('synced'); }),
    },
    ensureImagePullSecret: vi.fn().mockResolvedValue(null),
    renderManifest: vi.fn(async () => {
      order.push('render');
      return { manifestYaml: 'kind: List', services: {}, aliasIngresses: [], customDomainIngresses: [], desiredTcpIngressServices: [], serviceSecrets: [] };
    }),
  });
  return { deployer, k8s, egress, order };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
  mocks.profiles = {};
});

describe('deploy: egress.allow_hosts', () => {
  it('refuses a strict project when no FQDN provider is set, before any policy or workload', async () => {
    mocks.profiles = { 'egress.default_deny': 'strict', 'egress.allow_hosts': 'strict' };
    const { deployer, egress, k8s } = deployerFor();

    await expect(deployer.deploy('env_prod', 'rel_1', { skipPreflight: true }))
      .rejects.toThrow('egress allow lists need a provider (EVE_EGRESS_FQDN_PROVIDER)');
    expect(egress.applyEnv).not.toHaveBeenCalled();
    expect(k8s.applyManifest).not.toHaveBeenCalled();
  });

  it('with the GKE provider passes the profile and the release manifest to the env policies, before the workloads', async () => {
    vi.stubEnv('EVE_EGRESS_FQDN_PROVIDER', 'gke');
    mocks.profiles = { 'egress.default_deny': 'strict', 'egress.allow_hosts': 'strict' };
    const { deployer, egress, order } = deployerFor();

    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(egress.applyEnv).toHaveBeenCalledWith(
      { id: 'env_prod', projectId: 'proj_shop', name: 'prod', namespace: 'eve-acme-shop-prod' },
      'strict',
      { allowHosts: 'strict', manifest: expect.objectContaining({ 'x-eve': { egress: { hosts: ['api.example.com'] } } }) },
    );
    expect(order.filter((step) => step !== 'synced')).toEqual(['render', 'env:strict', 'runners:strict', 'workloads']);
  });

  it("marks the release's manifest as the project's last explicit sync or deploy before the runner policies", async () => {
    vi.stubEnv('EVE_EGRESS_FQDN_PROVIDER', 'gke');
    mocks.profiles = { 'egress.default_deny': 'strict', 'egress.allow_hosts': 'strict' };
    const { deployer, order } = deployerFor();
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect((deployer as any).manifests.markSynced).toHaveBeenCalledWith('man_1');
    expect(order.indexOf('synced')).toBeGreaterThanOrEqual(0);
    expect(order.indexOf('synced')).toBeLessThan(order.indexOf('runners:strict'));
  });

  it('under audit with no provider deploys as before', async () => {
    mocks.profiles = { 'egress.default_deny': 'audit', 'egress.allow_hosts': 'audit' };
    const { deployer, k8s } = deployerFor();
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(k8s.applyManifest).toHaveBeenCalled();
  });
});
