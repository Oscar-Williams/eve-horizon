import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EgressPolicies, type NetworkPolicyApi } from './egress-policies.js';

/**
 * egress.default_deny in the worker: env namespaces and per-project runner
 * policies written from what the database says the project needs, brought
 * into line with the project's profile at deploy, dispatch and reconcile.
 * The Kubernetes API is an in-memory fake.
 */
const db = vi.hoisted(() => ({
  profiles: new Map<string, 'legacy' | 'audit' | 'strict'>(),
  settings: new Map<string, string>(),
  projects: new Map<string, { id: string; org_id: string; slug: string; deleted_at?: Date | null }>(),
  orgs: new Map<string, { id: string; slug: string }>(),
  envs: [] as Array<{ id: string; project_id: string; name: string; namespace: string | null; status: string }>,
  tenants: [] as Array<{ id: string; env_id: string; instance_id: string; status: string }>,
  instances: new Map<string, { id: string; host: string; port: number }>(),
  subscriptions: [] as Array<Record<string, any>>,
  manifests: new Map<string, string>(),
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  // egress.allow_hosts stays legacy here (egress-allow-hosts.spec.ts covers it).
  governingSecurityProfile: vi.fn(async (_db: unknown, ctx: { projectId: string; rule: string }) => {
    expect(['egress.default_deny', 'egress.allow_hosts']).toContain(ctx.rule);
    return ctx.rule === 'egress.default_deny' ? db.profiles.get(ctx.projectId) ?? 'legacy' : 'legacy';
  }),
  systemSettingsQueries: () => ({
    get: async (key: string) => (db.settings.has(key) ? { key, value: db.settings.get(key) } : null),
  }),
  projectQueries: () => ({
    findById: async (id: string) => db.projects.get(id) ?? null,
  }),
  orgQueries: () => ({
    findById: async (id: string) => db.orgs.get(id) ?? null,
  }),
  environmentQueries: () => ({
    listByProject: async (projectId: string) => db.envs.filter((e) => e.project_id === projectId),
    findByProjectAndName: async (projectId: string, name: string) =>
      db.envs.find((e) => e.project_id === projectId && e.name === name) ?? null,
  }),
  managedDbQueries: () => ({
    listTenantsByEnv: async (envId: string) => db.tenants.filter((t) => t.env_id === envId),
    findInstanceById: async (id: string) => db.instances.get(id) ?? null,
  }),
  appLinkSubscriptionQueries: () => ({
    listWithGrants: async (options: { consumer_project_id: string }) =>
      db.subscriptions.filter((s) => s.consumer_project_id === options.consumer_project_id),
  }),
  projectManifestQueries: () => ({
    findLatestByProject: async (projectId: string) =>
      (db.manifests.has(projectId) ? { manifest_yaml: db.manifests.get(projectId) } : null),
  }),
  securityQueries: () => ({
    listProjectProfiles: async (scope: { orgId?: string; projectId?: string }) =>
      [...db.projects.values()]
        .filter((p) => !p.deleted_at)
        .filter((p) => (scope.projectId ? p.id === scope.projectId : true))
        .filter((p) => (scope.orgId ? p.org_id === scope.orgId : true))
        .map((p) => ({ id: p.id, slug: p.slug, org_id: p.org_id, security_profile: null })),
  }),
}));

type Policy = { metadata: { name: string; namespace: string; labels: Record<string, string> }; spec: any };

/** An in-memory cluster: namespaces and the NetworkPolicies in them. */
function fakeCluster(namespaces: string[]) {
  const nsSet = new Set(namespaces);
  const store = new Map<string, Policy>();
  const writes: string[] = [];
  const deletes: string[] = [];
  const key = (ns: string, name: string) => `${ns}/${name}`;
  const api: NetworkPolicyApi = {
    getNamespaceLabels: vi.fn(async (name: string) => (nsSet.has(name) ? {} : null)),
    applyNetworkPolicy: vi.fn(async (policy: Policy) => {
      const { namespace, name } = policy.metadata;
      if (!nsSet.has(namespace)) throw Object.assign(new Error(`namespaces "${namespace}" not found`), { statusCode: 404 });
      const existing = store.get(key(namespace, name));
      if (existing && JSON.stringify(existing) === JSON.stringify(policy)) return false;
      store.set(key(namespace, name), JSON.parse(JSON.stringify(policy)));
      writes.push(key(namespace, name));
      return true;
    }),
    deleteNetworkPolicy: vi.fn(async (namespace: string, name: string) => {
      store.delete(key(namespace, name));
      deletes.push(key(namespace, name));
    }),
    listNetworkPolicies: vi.fn(async (namespace: string, selector: string) => {
      const wanted = selector.split(',').map((s) => s.split('='));
      return [...store.values()]
        .filter((p) => p.metadata.namespace === namespace)
        .filter((p) => wanted.every(([k, v]) => p.metadata.labels?.[k] === v))
        .map((p) => ({ name: p.metadata.name, labels: p.metadata.labels }));
    }),
    // No FQDN provider in these specs: never called.
    applyFqdnNetworkPolicy: vi.fn(async () => { throw new Error('unexpected FQDN write'); }),
    deleteFqdnNetworkPolicy: vi.fn(async () => { throw new Error('unexpected FQDN delete'); }),
    listFqdnNetworkPolicies: vi.fn(async () => { throw new Error('unexpected FQDN list'); }),
  };
  const names = (namespace: string) =>
    [...store.values()].filter((p) => p.metadata.namespace === namespace).map((p) => p.metadata.name).sort();
  const get = (namespace: string, name: string) => store.get(key(namespace, name));
  return { api, store, writes, deletes, names, get, nsSet };
}

const SHOP = 'proj_shop';
const API = 'proj_api';
const PROD = { id: 'env_prod', projectId: SHOP, name: 'prod', namespace: 'eve-acme-shop-prod' };
const runnerName = (name: string) => expect.stringMatching(new RegExp(`^eve-runner-${name}-[0-9a-f]{8}$`));

function egressFor(cluster: ReturnType<typeof fakeCluster>, resolveHost = vi.fn(async (_h: string) => ['10.40.0.9'])) {
  const logger = { log: vi.fn(), warn: vi.fn() };
  return { egress: new EgressPolicies({} as never, cluster.api, { logger, resolveHost }), logger, resolveHost };
}

beforeEach(() => {
  vi.unstubAllEnvs();
  db.profiles = new Map();
  db.settings = new Map();
  db.projects = new Map([
    [SHOP, { id: SHOP, org_id: 'org_acme', slug: 'shop' }],
    [API, { id: API, org_id: 'org_acme', slug: 'api' }],
  ]);
  db.orgs = new Map([['org_acme', { id: 'org_acme', slug: 'acme' }]]);
  db.envs = [
    { id: 'env_prod', project_id: SHOP, name: 'prod', namespace: null, status: 'active' },
    { id: 'env_staging', project_id: SHOP, name: 'staging', namespace: null, status: 'active' },
    { id: 'env_api_prod', project_id: API, name: 'prod', namespace: null, status: 'active' },
  ];
  db.tenants = [];
  db.instances = new Map();
  db.subscriptions = [];
  db.manifests = new Map([[API, 'services:\n  web:\n    image: web:1\n    ports: [3000]\n']]);
});

describe('env namespaces', () => {
  it('under audit writes the companion before the strict policies; strict then removes only the companion', async () => {
    const cluster = fakeCluster(['eve-acme-shop-prod']);
    const { egress } = egressFor(cluster);

    await egress.applyEnv(PROD, 'audit');
    expect(cluster.writes).toEqual([
      'eve-acme-shop-prod/eve-egress-audit', 'eve-acme-shop-prod/eve-egress', 'eve-acme-shop-prod/eve-egress-metadata',
    ]);

    cluster.writes.length = 0;
    const strict = await egress.applyEnv(PROD, 'strict');
    expect(cluster.writes).toEqual([]);
    expect(strict.removed).toEqual(['eve-egress-audit']);
    expect(cluster.names('eve-acme-shop-prod')).toEqual(['eve-egress', 'eve-egress-metadata']);
  });

  it('under legacy writes nothing and removes every env egress policy', async () => {
    const cluster = fakeCluster(['eve-acme-shop-prod']);
    const { egress } = egressFor(cluster);
    await egress.applyEnv(PROD, 'audit');

    const result = await egress.applyEnv(PROD, 'legacy');
    expect(result.applied).toEqual([]);
    expect(cluster.names('eve-acme-shop-prod')).toEqual([]);
  });

  it('resolves the profile of the project when none is given', async () => {
    db.profiles.set(SHOP, 'strict');
    const cluster = fakeCluster(['eve-acme-shop-prod']);
    const { egress } = egressFor(cluster);
    expect((await egress.applyEnv(PROD)).profile).toBe('strict');
    expect(cluster.names('eve-acme-shop-prod')).toEqual(['eve-egress', 'eve-egress-metadata']);
  });

  it('allows a managed database as a /32 on its port, resolving a host name and keeping a cluster host in-cluster', async () => {
    db.tenants = [
      { id: 't1', env_id: 'env_prod', instance_id: 'i_ip', status: 'ready' },
      { id: 't2', env_id: 'env_prod', instance_id: 'i_dns', status: 'ready' },
      { id: 't3', env_id: 'env_prod', instance_id: 'i_svc', status: 'ready' },
    ];
    db.instances = new Map([
      ['i_ip', { id: 'i_ip', host: '10.40.0.3', port: 5432 }],
      ['i_dns', { id: 'i_dns', host: 'db.internal.eve.example', port: 6432 }],
      ['i_svc', { id: 'i_svc', host: 'eve-postgres.eve.svc.cluster.local', port: 5432 }],
    ]);
    const cluster = fakeCluster(['eve-acme-shop-prod']);
    const { egress, resolveHost } = egressFor(cluster);

    await egress.applyEnv(PROD, 'strict');
    const rules = cluster.get('eve-acme-shop-prod', 'eve-egress')!.spec.egress;
    expect(resolveHost).toHaveBeenCalledWith('db.internal.eve.example');
    expect(rules).toContainEqual({ to: [{ ipBlock: { cidr: '10.40.0.3/32' } }], ports: [{ protocol: 'TCP', port: 5432 }] });
    expect(rules).toContainEqual({ to: [{ ipBlock: { cidr: '10.40.0.9/32' } }], ports: [{ protocol: 'TCP', port: 6432 }] });
    expect(rules).toContainEqual({
      to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve' } } }],
      ports: [{ protocol: 'TCP', port: 5432 }],
    });
  });

  it('allows an app-link producer namespace on the producer service port', async () => {
    db.subscriptions = [{
      id: 'sub_1', consumer_project_id: SHOP, local_alias: 'catalog', environment_strategy: 'same', producer_env_name: null,
      api_grant: { producer_project_id: API, service_name: 'web', envs: [], revoked_at: null },
    }];
    const cluster = fakeCluster(['eve-acme-shop-prod']);
    const { egress } = egressFor(cluster);

    await egress.applyEnv(PROD, 'strict');
    expect(cluster.get('eve-acme-shop-prod', 'eve-egress')!.spec.egress).toContainEqual({
      to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve-acme-api-prod' } } }],
      ports: [{ protocol: 'TCP', port: 3000 }],
    });
  });

  it('keeps network.private_cidrs out of the internet rule', async () => {
    db.settings.set('network.private_cidrs', '198.18.0.0/15');
    const cluster = fakeCluster(['eve-acme-shop-prod']);
    const { egress } = egressFor(cluster);

    await egress.applyEnv(PROD, 'strict');
    const internet = cluster.get('eve-acme-shop-prod', 'eve-egress')!.spec.egress
      .flatMap((rule: any) => rule.to ?? []).find((peer: any) => peer.ipBlock?.cidr === '0.0.0.0/0');
    expect(internet.ipBlock.except).toContain('198.18.0.0/15');
  });
});

describe('runner policies', () => {
  it('writes the project set in the runner and platform namespaces, with its env namespaces and producers', async () => {
    db.profiles.set(SHOP, 'strict');
    db.subscriptions = [{
      id: 'sub_1', consumer_project_id: SHOP, local_alias: 'catalog', environment_strategy: 'fixed', producer_env_name: 'prod',
      api_grant: { producer_project_id: API, service_name: 'web', envs: ['prod'], revoked_at: null },
    }];
    const cluster = fakeCluster(['eve-runners', 'eve']);
    const { egress } = egressFor(cluster);

    await egress.applyRunners(SHOP);
    expect(cluster.names('eve-runners')).toEqual([runnerName('proj-shop')]);
    expect(cluster.names('eve')).toEqual([runnerName('proj-shop')]);
    const [name] = cluster.names('eve-runners');
    const policy = cluster.get('eve-runners', name)!;
    expect(policy.spec.podSelector).toEqual({ matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': SHOP } });
    expect(policy.metadata.labels).toMatchObject({ 'eve.horizon/egress': 'runner', 'eve.horizon/project-id': SHOP });
    for (const ns of ['eve-acme-shop-prod', 'eve-acme-shop-staging']) {
      expect(policy.spec.egress).toContainEqual({ to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': ns } } }] });
    }
    expect(policy.spec.egress).toContainEqual({
      to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve-acme-api-prod' } } }],
      ports: [{ protocol: 'TCP', port: 3000 }],
    });
  });

  it("allows a job-only project's fixed-env app-link producers, which its jobs resolve with no environment", async () => {
    const JOBS = 'proj_jobs';
    db.projects.set(JOBS, { id: JOBS, org_id: 'org_acme', slug: 'jobs' });
    db.profiles.set(JOBS, 'strict');
    db.subscriptions = [
      { id: 'sub_fixed', consumer_project_id: JOBS, local_alias: 'catalog', environment_strategy: 'fixed', producer_env_name: 'prod',
        api_grant: { producer_project_id: API, service_name: 'web', envs: ['prod'], revoked_at: null } },
      // A same-env link has no producer env without an environment of its own, so jobs cannot resolve it.
      { id: 'sub_same', consumer_project_id: JOBS, local_alias: 'mirror', environment_strategy: 'same', producer_env_name: null,
        api_grant: { producer_project_id: API, service_name: 'web', envs: [], revoked_at: null } },
    ];
    const cluster = fakeCluster(['eve-runners']);
    const { egress } = egressFor(cluster);

    await egress.applyRunners(JOBS);
    const [name] = cluster.names('eve-runners');
    const peers = cluster.get('eve-runners', name)!.spec.egress
      .flatMap((rule: any) => (rule.to ?? []).map((peer: any) => peer.namespaceSelector?.matchLabels?.['kubernetes.io/metadata.name']))
      .filter(Boolean);
    expect(peers).toContain('eve-acme-api-prod');
    expect(peers.filter((ns: string) => ns.startsWith('eve-acme-api-'))).toEqual(['eve-acme-api-prod']);
  });

  it('skips a runner namespace the cluster does not have', async () => {
    const cluster = fakeCluster(['eve']);
    const { egress } = egressFor(cluster);
    await egress.applyRunners(SHOP, 'audit');
    expect(cluster.names('eve')).toHaveLength(2);
    expect(cluster.api.applyNetworkPolicy).not.toHaveBeenCalledWith(expect.objectContaining({
      metadata: expect.objectContaining({ namespace: 'eve-runners' }),
    }));
  });

  it('at dispatch writes only when the set is missing or out of line with the profile', async () => {
    db.profiles.set(SHOP, 'audit');
    const cluster = fakeCluster(['eve-runners', 'eve']);
    const { egress } = egressFor(cluster);

    expect(await egress.ensureRunnersForDispatch(SHOP)).toBe('written');
    expect(cluster.names('eve-runners')).toEqual([runnerName('proj-shop'), expect.stringMatching(/^eve-runner-proj-shop-[0-9a-f]{8}-audit$/)]);

    vi.mocked(cluster.api.applyNetworkPolicy).mockClear();
    expect(await egress.ensureRunnersForDispatch(SHOP)).toBe('current');
    expect(cluster.api.applyNetworkPolicy).not.toHaveBeenCalled();
    expect(cluster.api.deleteNetworkPolicy).not.toHaveBeenCalled();

    db.profiles.set(SHOP, 'strict');
    expect(await egress.ensureRunnersForDispatch(SHOP)).toBe('written');
    expect(cluster.names('eve-runners')).toEqual([runnerName('proj-shop')]);
    expect(cluster.names('eve')).toEqual([runnerName('proj-shop')]);
  });

  it('gives a legacy project only the allow-all companion, which the static deny needs', async () => {
    const cluster = fakeCluster(['eve-runners', 'eve']);
    const { egress } = egressFor(cluster);
    await egress.ensureRunnersForDispatch(SHOP);
    const [name] = cluster.names('eve-runners');
    expect(name).toMatch(/-audit$/);
    expect(cluster.get('eve-runners', name)!.spec.egress).toEqual([{}]);
  });
});

describe('reconcile', () => {
  it('after a profile flip removes the companions of the project, in env namespaces and runner policies, with no deploy', async () => {
    db.profiles.set(SHOP, 'audit');
    const cluster = fakeCluster(['eve-acme-shop-prod', 'eve-acme-shop-staging', 'eve-runners', 'eve']);
    const { egress } = egressFor(cluster);
    await egress.reconcile({ projectId: SHOP });
    expect(cluster.names('eve-acme-shop-prod')).toContain('eve-egress-audit');

    db.profiles.set(SHOP, 'strict');
    const report = await egress.reconcile({ projectId: SHOP });
    for (const ns of ['eve-acme-shop-prod', 'eve-acme-shop-staging']) {
      expect(cluster.names(ns)).toEqual(['eve-egress', 'eve-egress-metadata']);
    }
    expect(cluster.names('eve-runners')).toEqual([runnerName('proj-shop')]);
    expect(report.environments).toMatchObject({ reconciled: 2, without_namespace: 0, failed: [] });
    expect(report.runners).toMatchObject({ projects: 1, failed: [] });
  });

  it('counts envs whose namespace does not exist, and only touches the projects in scope', async () => {
    db.profiles.set(SHOP, 'audit');
    db.profiles.set(API, 'audit');
    const cluster = fakeCluster(['eve-acme-shop-prod', 'eve-runners', 'eve']);
    const { egress } = egressFor(cluster);

    const report = await egress.reconcile({ projectId: SHOP });
    expect(report.environments).toMatchObject({ reconciled: 1, without_namespace: 1 });
    expect(cluster.names('eve-runners')).toHaveLength(2);
  });

  it('deletes the runner policies of a deleted project, and none of the others', async () => {
    const cluster = fakeCluster(['eve-runners', 'eve']);
    const { egress } = egressFor(cluster);
    await egress.reconcile();
    expect(cluster.names('eve-runners')).toHaveLength(2);

    db.projects.get(API)!.deleted_at = new Date();
    const report = await egress.reconcile();
    expect(report.runners.orphans_removed).toBe(2);
    expect(cluster.names('eve-runners')).toEqual([expect.stringMatching(/^eve-runner-proj-shop-/)]);
    expect(cluster.names('eve')).toEqual([expect.stringMatching(/^eve-runner-proj-shop-/)]);
  });

  it('reports a failed env and carries on with the rest', async () => {
    db.profiles.set(SHOP, 'audit');
    const cluster = fakeCluster(['eve-acme-shop-prod', 'eve-acme-shop-staging', 'eve-runners', 'eve']);
    const apply = cluster.api.applyNetworkPolicy;
    vi.mocked(apply).mockImplementation(async (policy: any) => {
      if (policy.metadata.namespace === 'eve-acme-shop-prod') throw Object.assign(new Error('forbidden'), { statusCode: 403 });
      return true;
    });
    const { egress } = egressFor(cluster);

    const report = await egress.reconcile({ projectId: SHOP });
    expect(report.environments.failed).toEqual([{ environment_id: 'env_prod', error: expect.stringContaining('forbidden') }]);
    expect(report.environments.reconciled).toBe(1);
    expect(report.runners.failed).toEqual([]);
  });
});
