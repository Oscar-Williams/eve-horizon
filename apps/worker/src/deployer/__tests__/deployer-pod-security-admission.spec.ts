import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DeployerService } from '../deployer.service.js';

// isolation.pod_security_admission at deploy: under strict the env namespace
// gets warn and audit before the workloads and enforce at its level only once
// the rollout has succeeded (old pods that do not meet it would otherwise be
// stranded); under audit it carries warn and audit only; an enforce label Eve
// set goes when the profile drops, one it did not set stays. Each strict or
// audit deploy is recorded.

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
const PSA = 'pod-security.kubernetes.io';
const ENFORCE = `${PSA}/enforce`;
const MARK = 'eve.horizon/pod-security-enforce';

function deployerFor(
  current: { labels?: Record<string, string>; annotations?: Record<string, string> } = {},
  level: 'restricted' | 'baseline' = 'restricted',
  rollout: 'ready' | 'not_ready' | 'fails' = 'ready',
) {
  const order: string[] = [];
  const k8s = {
    createNamespace: vi.fn(async () => undefined),
    getNamespaceMetadata: vi.fn(async () => ({
      labels: { 'eve.env_id': 'env_prod', ...(current.labels ?? {}) },
      annotations: { ...(current.annotations ?? {}) },
    })),
    patchNamespaceMetadata: vi.fn(async (_ns: string, patch: { labels: Record<string, string | null>; annotations: Record<string, string | null> }) => {
      order.push(`patch:${JSON.stringify(patch)}`);
    }),
    applyManifest: vi.fn(async () => {
      order.push('workloads');
      if (rollout === 'fails') throw new Error('admission webhook denied the request');
    }),
    listAliasIngresses: vi.fn(async () => []),
    listCustomDomainIngresses: vi.fn(async () => []),
    listSecrets: vi.fn(async () => []),
    listPodsWithLabel: vi.fn(async () => []),
    deleteSecret: vi.fn(),
    deploymentExists: vi.fn(async () => false),
    getDeploymentStatus: vi.fn(async () => {
      order.push('rollout');
      return { ready: rollout === 'ready', availableReplicas: 0, desiredReplicas: 0, conditions: [] };
    }),
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
    manifests: { findByProjectAndHash: vi.fn().mockResolvedValue({ id: 'man_1', manifest_yaml: 'services: {}' }), markSynced: vi.fn() },
    ensureImagePullSecret: vi.fn().mockResolvedValue(null),
    renderManifest: vi.fn(async () => ({
      manifestYaml: 'kind: List', services: {}, aliasIngresses: [], customDomainIngresses: [],
      desiredTcpIngressServices: [], serviceSecrets: [], podSecurityLevel: level,
    })),
  });
  const patches = () => k8s.patchNamespaceMetadata.mock.calls.map((call) => call[1]);
  return { deployer, k8s, order, patches };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.unstubAllEnvs();
  mocks.profiles = {};
  mocks.decided = [];
});

describe('deploy: isolation.pod_security_admission', () => {
  it('under strict sets warn and audit before the workloads, and enforce (pinned, marked) only after the rollout succeeded', async () => {
    mocks.profiles = { 'isolation.pod_security': 'strict', 'isolation.pod_security_admission': 'strict' };
    const { deployer, order, patches } = deployerFor({}, 'baseline');
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });

    const [before, after] = patches();
    expect(before).toEqual({ labels: { [`${PSA}/warn`]: 'baseline', [`${PSA}/audit`]: 'baseline' }, annotations: {} });
    expect(after.labels).toEqual(expect.objectContaining({ [ENFORCE]: 'baseline', [`${PSA}/enforce-version`]: 'v1.30' }));
    expect(after.annotations).toEqual({ [MARK]: 'baseline' });
    const enforceAt = order.findIndex((o) => o.includes(`"${ENFORCE}":"baseline"`));
    expect(enforceAt).toBeGreaterThan(order.indexOf('rollout'));
    expect(order.findIndex((o) => o.startsWith('patch:'))).toBeLessThan(order.indexOf('workloads'));
    expect(mocks.decided).toContainEqual(expect.objectContaining({
      rule: 'isolation.pod_security_admission', detail: expect.objectContaining({ env: 'prod', level: 'baseline' }),
    }));
  });

  it('pins enforce-version to EVE_POD_SECURITY_VERSION', async () => {
    vi.stubEnv('EVE_POD_SECURITY_VERSION', 'v1.32');
    mocks.profiles = { 'isolation.pod_security': 'strict', 'isolation.pod_security_admission': 'strict' };
    const { deployer, patches } = deployerFor();
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(patches().at(-1)!.labels[`${PSA}/enforce-version`]).toBe('v1.32');
  });

  it('leaves enforce as it was when the rollout fails or does not finish', async () => {
    mocks.profiles = { 'isolation.pod_security': 'strict', 'isolation.pod_security_admission': 'strict' };
    const failed = deployerFor({}, 'restricted', 'fails');
    await expect(failed.deployer.deploy('env_prod', 'rel_1', { skipPreflight: true })).rejects.toThrow();
    expect(failed.patches().some((p) => ENFORCE in p.labels)).toBe(false);

    const slow = deployerFor({}, 'restricted', 'not_ready');
    await slow.deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(slow.patches().some((p) => ENFORCE in p.labels)).toBe(false);
  });

  it('under strict lowers an enforce Eve set before the workloads when the level drops', async () => {
    mocks.profiles = { 'isolation.pod_security': 'strict', 'isolation.pod_security_admission': 'strict' };
    const { deployer, order, patches } = deployerFor(
      { labels: { [ENFORCE]: 'restricted', [`${PSA}/enforce-version`]: 'v1.30' }, annotations: { [MARK]: 'restricted' } },
      'baseline',
    );
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(patches()[0].labels[ENFORCE]).toBe('baseline');
    expect(order.findIndex((o) => o.includes(`"${ENFORCE}":"baseline"`))).toBeLessThan(order.indexOf('workloads'));
  });

  it('under audit sets warn and audit, and removes an enforce Eve set', async () => {
    mocks.profiles = { 'isolation.pod_security_admission': 'audit' };
    const { deployer, patches } = deployerFor({ labels: { [ENFORCE]: 'restricted', [`${PSA}/enforce-version`]: 'v1.30' }, annotations: { [MARK]: 'restricted' } });
    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(patches()).toEqual([{
      labels: { [ENFORCE]: null, [`${PSA}/enforce-version`]: null, [`${PSA}/warn`]: 'restricted', [`${PSA}/audit`]: 'restricted' },
      annotations: { [MARK]: null },
    }]);
  });

  it('under legacy leaves an enforce Eve did not set, and writes nothing to a namespace that never enforced', async () => {
    const operators = deployerFor({ labels: { [ENFORCE]: 'baseline' } });
    await operators.deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(operators.k8s.patchNamespaceMetadata).not.toHaveBeenCalled();

    const plain = deployerFor({});
    await plain.deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(plain.k8s.patchNamespaceMetadata).not.toHaveBeenCalled();
    expect(mocks.decided.filter((d) => d.rule === 'isolation.pod_security_admission')).toEqual([]);
  });
});

// A service job (a migration) runs before the deploy that would lower the
// namespace's enforce: once a strict deploy set enforce=restricted, a job
// that opts out (run_as_root) would be refused and a migrate-then-deploy
// pipeline would never reach the deploy. Before it runs, an enforce Eve set
// that is stricter than the job's level is lowered to it.
function jobDeployerFor(current: { labels?: Record<string, string>; annotations?: Record<string, string> } = {}) {
  const order: string[] = [];
  const k8s = {
    createNamespace: vi.fn(async () => undefined),
    getNamespaceMetadata: vi.fn(async () => ({
      labels: { 'eve.env_id': 'env_prod', ...(current.labels ?? {}) },
      annotations: { ...(current.annotations ?? {}) },
    })),
    patchNamespaceMetadata: vi.fn(async (_ns: string, patch: { labels: Record<string, string | null>; annotations: Record<string, string | null> }) => {
      order.push(`patch:${JSON.stringify(patch)}`);
    }),
    applyManifest: vi.fn(async () => undefined),
    deleteSecret: vi.fn(),
    runJob: vi.fn(async () => {
      order.push('job');
      return { jobName: 'job', success: true, exitCode: 0, logs: '' };
    }),
  };
  const deployer = new DeployerService(null as any, k8s as any);
  Object.assign(deployer as any, {
    logger: { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() },
    egress: {
      applyEnv: vi.fn(async () => ({ profile: 'legacy', applied: [], removed: [] })),
      applyRunners: vi.fn(async () => ({ profile: 'legacy', applied: [], removed: [] })),
    },
    environments: {
      findByProjectAndName: vi.fn().mockResolvedValue({ id: 'env_prod', project_id: 'proj_shop', name: 'prod', namespace: null, overrides_json: null }),
    },
    projects: { findById: vi.fn().mockResolvedValue({ id: 'proj_shop', org_id: 'org_acme', slug: 'shop', repo_url: null }) },
    orgs: { findById: vi.fn().mockResolvedValue({ id: 'org_acme', slug: 'acme' }) },
  });
  vi.spyOn(deployer as any, 'ensureImagePullSecret').mockResolvedValue(null);
  vi.spyOn(deployer as any, 'waitForJobDependencies').mockResolvedValue(undefined);
  const patches = () => k8s.patchNamespaceMetadata.mock.calls.map((call) => call[1]);
  return { deployer, k8s, order, patches };
}

function migrateJob(security: Record<string, unknown>) {
  return {
    projectId: 'proj_shop',
    envName: 'prod',
    manifestYaml: `services:\n  migrate:\n    image: registry.example/migrate:1\n    x-eve:\n      role: job\n      security: ${JSON.stringify(security)}\n`,
    serviceName: 'migrate',
    attemptId: 'attempt_12345678',
  };
}

describe('service job: isolation.pod_security_admission', () => {
  const restrictedByEve = { labels: { [ENFORCE]: 'restricted', [`${PSA}/enforce-version`]: 'v1.30' }, annotations: { [MARK]: 'restricted' } };

  it('lowers an enforce Eve set at restricted before a job that needs baseline runs', async () => {
    mocks.profiles = { 'isolation.pod_security': 'strict', 'isolation.pod_security_admission': 'strict' };
    const { deployer, order, patches } = jobDeployerFor(restrictedByEve);
    await deployer.runJobService(migrateJob({ run_as_root: true }));

    expect(patches()).toEqual([{ labels: { [ENFORCE]: 'baseline' }, annotations: { [MARK]: 'baseline' } }]);
    expect(order.findIndex((o) => o.startsWith('patch:'))).toBeLessThan(order.indexOf('job'));
  });

  it('never raises enforce, and leaves one Eve did not set', async () => {
    mocks.profiles = { 'isolation.pod_security': 'strict', 'isolation.pod_security_admission': 'strict' };
    const restricted = jobDeployerFor({ labels: { [ENFORCE]: 'baseline' }, annotations: { [MARK]: 'baseline' } });
    await restricted.deployer.runJobService(migrateJob({ run_as_user: 1000 }));
    expect(restricted.k8s.patchNamespaceMetadata).not.toHaveBeenCalled();

    const operators = jobDeployerFor({ labels: { [ENFORCE]: 'restricted' } });
    await operators.deployer.runJobService(migrateJob({ run_as_root: true }));
    expect(operators.k8s.patchNamespaceMetadata).not.toHaveBeenCalled();
  });

  it('reads no namespace labels under legacy', async () => {
    mocks.profiles = { 'isolation.pod_security': 'strict' };
    const { deployer, k8s } = jobDeployerFor(restrictedByEve);
    await deployer.runJobService(migrateJob({ run_as_root: true }));
    expect(k8s.getNamespaceMetadata).not.toHaveBeenCalled();
    expect(k8s.patchNamespaceMetadata).not.toHaveBeenCalled();
  });
});
