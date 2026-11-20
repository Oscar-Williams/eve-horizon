import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DeployerService } from '../deployer.service.js';

// isolation.pod_security_admission at deploy: under strict the env namespace
// enforces its Pod Security level before any workload is applied; under
// audit it carries warn and audit only; an enforce label a strict profile
// left goes when the profile drops. Each strict or audit deploy is recorded.

const mocks = vi.hoisted(() => ({
  profiles: {} as Record<string, 'legacy' | 'audit' | 'strict'>,
  decided: [] as Array<{ rule: string; detail: Record<string, unknown> }>,
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: vi.fn(async (_db: unknown, rule: string, ctx: { detail?: Record<string, unknown> }) => {
    mocks.decided.push({ rule, detail: ctx.detail ?? {} });
    return mocks.profiles[rule] ?? 'legacy';
  }),
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

const NS = 'eve-acme-shop-prod';
const ENFORCE = 'pod-security.kubernetes.io/enforce';

function deployerFor(current: Record<string, string> = {}, level: 'restricted' | 'baseline' = 'restricted') {
  const order: string[] = [];
  const k8s = {
    createNamespace: vi.fn(async () => undefined),
    getNamespaceLabels: vi.fn(async () => ({ 'eve.env_id': 'env_prod', ...current })),
    setNamespaceLabels: vi.fn(async (_ns: string, labels: Record<string, string | null>) => { order.push(`labels:${JSON.stringify(labels)}`); }),
    applyManifest: vi.fn(async () => { order.push('workloads'); }),
    listAliasIngresses: vi.fn(async () => []),
    listCustomDomainIngresses: vi.fn(async () => []),
    listSecrets: vi.fn(async () => []),
    deleteSecret: vi.fn(),
    deploymentExists: vi.fn(async () => false),
    getDeploymentStatus: vi.fn(async () => ({ ready: true, availableReplicas: 0, desiredReplicas: 0, conditions: [] })),
  };
  const deployer = new DeployerService(null as any, k8s as any);
  Object.assign(deployer as any, {
    logger: { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() },
    egress: {
      applyEnv: vi.fn(async () => ({ profile: 'legacy', applied: [], removed: [] })),
      applyRunners: vi.fn(async () => ({ profile: 'legacy', applied: [], removed: [] })),
    },
    environments: {
      findById: vi.fn().mockResolvedValue({ id: 'env_prod', project_id: 'proj_shop', name: 'prod', namespace: null, overrides_json: null }),
    },
    releases: {
      findById: vi.fn().mockResolvedValue({ id: 'rel_1', project_id: 'proj_shop', manifest_hash: 'h', image_digests_json: null }),
    },
    projects: { findById: vi.fn().mockResolvedValue({ id: 'proj_shop', org_id: 'org_acme', slug: 'shop', repo_url: null }) },
    orgs: { findById: vi.fn().mockResolvedValue({ id: 'org_acme', slug: 'acme' }) },
    manifests: { findByProjectAndHash: vi.fn().mockResolvedValue({ manifest_yaml: 'services: {}' }) },
    ensureImagePullSecret: vi.fn().mockResolvedValue(null),
    renderManifest: vi.fn(async () => ({
      manifestYaml: 'kind: List', services: {}, aliasIngresses: [], customDomainIngresses: [],
      desiredTcpIngressServices: [], serviceSecrets: [], podSecurityLevel: level,
    })),
  });
  return { deployer, k8s, order };
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profiles = {};
  mocks.decided = [];
});

describe('deploy: isolation.pod_security_admission', () => {
  it('under strict labels the namespace enforce at its level before the workloads, and records it', async () => {
    mocks.profiles = { 'isolation.pod_security': 'strict', 'isolation.pod_security_admission': 'strict' };
    const { deployer, k8s, order } = deployerFor({}, 'baseline');
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });

    expect(k8s.setNamespaceLabels).toHaveBeenCalledWith(NS, expect.objectContaining({
      [ENFORCE]: 'baseline', 'pod-security.kubernetes.io/enforce-version': 'latest',
    }));
    expect(order.findIndex((o) => o.startsWith('labels:'))).toBeLessThan(order.indexOf('workloads'));
    expect(mocks.decided).toContainEqual(expect.objectContaining({
      rule: 'isolation.pod_security_admission', detail: expect.objectContaining({ env: 'prod', level: 'baseline' }),
    }));
  });

  it('under audit sets warn and audit, and removes an enforce left behind', async () => {
    mocks.profiles = { 'isolation.pod_security_admission': 'audit' };
    const { deployer, k8s } = deployerFor({ [ENFORCE]: 'restricted' });
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(k8s.setNamespaceLabels).toHaveBeenCalledWith(NS, {
      [ENFORCE]: null,
      'pod-security.kubernetes.io/warn': 'restricted',
      'pod-security.kubernetes.io/audit': 'restricted',
    });
  });

  it('under legacy writes nothing to a namespace that never enforced', async () => {
    const { deployer, k8s } = deployerFor({});
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(k8s.setNamespaceLabels).not.toHaveBeenCalled();
    expect(mocks.decided.filter((d) => d.rule === 'isolation.pod_security_admission')).toEqual([]);
  });
});
