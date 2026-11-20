import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EgressPolicies } from './egress-policies.js';

/**
 * network.ingress_isolation in the worker: each env namespace gets
 * `eve-ingress` (and under audit the allow-all `eve-ingress-audit`) from
 * what the database says may call it: the project's own env namespaces and
 * runners, and the projects that consume its app links. The egress sync and
 * the ingress sync each delete only their own policies.
 */
const db = vi.hoisted(() => ({
  profiles: new Map<string, Record<string, 'legacy' | 'audit' | 'strict'>>(),
  projects: new Map<string, { id: string; org_id: string; slug: string; repo_url: string | null }>(),
  orgs: new Map<string, { id: string; slug: string }>(),
  envs: [] as Array<Record<string, any>>,
  subscriptions: [] as Array<Record<string, any>>,
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  governingSecurityProfile: vi.fn(async (_db: unknown, ctx: { projectId: string; rule: string }) =>
    db.profiles.get(ctx.projectId)?.[ctx.rule] ?? 'legacy'),
  decideSecurityRule: vi.fn(async () => 'legacy'),
  systemSettingsQueries: () => ({ get: async () => null }),
  projectQueries: () => ({ findById: async (id: string) => db.projects.get(id) ?? null }),
  orgQueries: () => ({ findById: async (id: string) => db.orgs.get(id) ?? null }),
  environmentQueries: () => ({
    listByProject: async (projectId: string) => db.envs.filter((e) => e.project_id === projectId),
    findByProjectAndName: async (projectId: string, name: string) =>
      db.envs.find((e) => e.project_id === projectId && e.name === name) ?? null,
    findById: async (id: string) => db.envs.find((e) => e.id === id) ?? null,
  }),
  releaseQueries: () => ({ findById: async () => null }),
  managedDbQueries: () => ({ listTenantsByEnv: async () => [], findInstanceById: async () => null }),
  appLinkSubscriptionQueries: () => ({
    listWithGrants: async (options: { consumer_project_id?: string; producer_project_id?: string }) =>
      db.subscriptions
        .filter((s) => (options.consumer_project_id ? s.consumer_project_id === options.consumer_project_id : true))
        .filter((s) => (options.producer_project_id ? s.api_grant?.producer_project_id === options.producer_project_id : true)),
  }),
  projectManifestQueries: () => ({
    findLatestByProject: async () => null,
    findLatestSyncedByProject: async () => null,
    findByProjectAndHash: async () => null,
  }),
  securityQueries: () => ({
    listProjectProfiles: async () => [...db.projects.values()].map((p) => ({ id: p.id, slug: p.slug, org_id: p.org_id })),
  }),
}));

type Policy = { metadata: { name: string; namespace: string; labels: Record<string, string> }; spec: any };

function fakeCluster(namespaces: string[]) {
  const nsSet = new Set(namespaces);
  const store = new Map<string, Policy>();
  const writes: string[] = [];
  const key = (ns: string, name: string) => `${ns}/${name}`;
  const api = {
    getNamespaceLabels: vi.fn(async (name: string) => (nsSet.has(name) ? {} : null)),
    applyNetworkPolicy: vi.fn(async (policy: Policy) => {
      const { namespace, name } = policy.metadata;
      const existing = store.get(key(namespace, name));
      if (existing && JSON.stringify(existing) === JSON.stringify(policy)) return false;
      store.set(key(namespace, name), JSON.parse(JSON.stringify(policy)));
      writes.push(key(namespace, name));
      return true;
    }),
    deleteNetworkPolicy: vi.fn(async (namespace: string, name: string) => { store.delete(key(namespace, name)); }),
    listNetworkPolicies: vi.fn(async (namespace: string, selector: string) => {
      const wanted = selector.split(',').map((s) => s.split('='));
      return [...store.values()]
        .filter((p) => p.metadata.namespace === namespace)
        .filter((p) => wanted.every(([k, v]) => p.metadata.labels?.[k] === v))
        .map((p) => ({ name: p.metadata.name, labels: p.metadata.labels }));
    }),
    applyFqdnNetworkPolicy: vi.fn(),
    deleteFqdnNetworkPolicy: vi.fn(),
    listFqdnNetworkPolicies: vi.fn(async () => []),
  };
  const names = (namespace: string) => [...store.values()].filter((p) => p.metadata.namespace === namespace).map((p) => p.metadata.name).sort();
  return { api, store, writes, names, get: (ns: string, name: string) => store.get(key(ns, name)) };
}

const SHOP = 'proj_shop';
const PORTAL = 'proj_portal';
const PROD = { id: 'env_prod', projectId: SHOP, name: 'prod', namespace: 'eve-acme-shop-prod' };
const nsPeer = (ns: string) => ({ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': ns } } });
const runnerPeer = (ns: string, project: string) => ({
  namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': ns } },
  podSelector: { matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': project } },
});

function egressFor(cluster: ReturnType<typeof fakeCluster>) {
  return new EgressPolicies({} as never, cluster.api as never, { logger: { log: vi.fn(), warn: vi.fn() }, resolveHost: async () => [] });
}

beforeEach(() => {
  vi.unstubAllEnvs();
  vi.stubEnv('EVE_RUNNER_NAMESPACE', 'eve-runners');
  vi.stubEnv('EVE_K8S_NAMESPACE', 'eve');
  db.profiles = new Map();
  db.projects = new Map([
    [SHOP, { id: SHOP, org_id: 'org_acme', slug: 'shop', repo_url: null }],
    [PORTAL, { id: PORTAL, org_id: 'org_acme', slug: 'portal', repo_url: null }],
    ['proj_other', { id: 'proj_other', org_id: 'org_acme', slug: 'other', repo_url: null }],
  ]);
  db.orgs = new Map([['org_acme', { id: 'org_acme', slug: 'acme' }]]);
  db.envs = [
    { id: 'env_prod', project_id: SHOP, name: 'prod', namespace: null, status: 'active' },
    { id: 'env_staging', project_id: SHOP, name: 'staging', namespace: null, status: 'active' },
    { id: 'env_portal_prod', project_id: PORTAL, name: 'prod', namespace: null, status: 'active' },
    { id: 'env_portal_staging', project_id: PORTAL, name: 'staging', namespace: null, status: 'active' },
    { id: 'env_other_prod', project_id: 'proj_other', name: 'prod', namespace: null, status: 'active' },
  ];
  // The portal consumes the shop's API in the env of the same name; a revoked grant counts for nothing.
  db.subscriptions = [
    { consumer_project_id: PORTAL, environment_strategy: 'same', producer_env_name: null,
      api_grant: { producer_project_id: SHOP, service_name: 'api', envs: [], revoked_at: null } },
    { consumer_project_id: 'proj_other', environment_strategy: 'fixed', producer_env_name: 'prod',
      api_grant: { producer_project_id: SHOP, service_name: 'api', envs: [], revoked_at: new Date() } },
  ];
});

describe('env namespaces: network.ingress_isolation', () => {
  it('under strict writes eve-ingress from the project, its runners and its live app-link consumers', async () => {
    db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict' });
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    await egressFor(cluster).applyEnv(PROD);

    expect(cluster.names(PROD.namespace)).toEqual(['eve-ingress']);
    const from = cluster.get(PROD.namespace, 'eve-ingress')!.spec.ingress[0].from;
    expect(from).toEqual(expect.arrayContaining([
      nsPeer('eve-acme-shop-prod'), nsPeer('eve-acme-shop-staging'), nsPeer('eve-acme-portal-prod'),
      runnerPeer('eve-runners', SHOP), runnerPeer('eve-runners', PORTAL), runnerPeer('eve', SHOP),
    ]));
    expect(from).not.toContainEqual(nsPeer('eve-acme-portal-staging'));
    expect(from).not.toContainEqual(nsPeer('eve-acme-other-prod'));
    expect(from).not.toContainEqual(runnerPeer('eve-runners', 'proj_other'));
  });

  it('a fixed-env consumer: every env namespace of the consumer may call that producer env', async () => {
    db.subscriptions = [{ consumer_project_id: PORTAL, environment_strategy: 'fixed', producer_env_name: 'prod',
      api_grant: { producer_project_id: SHOP, service_name: 'api', envs: [], revoked_at: null } }];
    db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict' });
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    await egressFor(cluster).applyEnv(PROD);
    const from = cluster.get(PROD.namespace, 'eve-ingress')!.spec.ingress[0].from;
    expect(from).toEqual(expect.arrayContaining([nsPeer('eve-acme-portal-prod'), nsPeer('eve-acme-portal-staging')]));

    // The shop's staging env is not that producer env: the portal may not call it.
    await egressFor(cluster).applyEnv({ id: 'env_staging', projectId: SHOP, name: 'staging', namespace: 'eve-acme-shop-staging' });
    const staging = cluster.get('eve-acme-shop-staging', 'eve-ingress')!.spec.ingress[0].from;
    expect(staging).not.toContainEqual(nsPeer('eve-acme-portal-prod'));
    expect(staging).not.toContainEqual(runnerPeer('eve-runners', PORTAL));
    expect(staging).toContainEqual(nsPeer('eve-acme-shop-prod'));
  });

  it('under audit writes the allow-all companion first; legacy removes both', async () => {
    db.profiles.set(SHOP, { 'network.ingress_isolation': 'audit' });
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await egress.applyEnv(PROD);
    expect(cluster.writes).toEqual([`${PROD.namespace}/eve-ingress-audit`, `${PROD.namespace}/eve-ingress`]);

    db.profiles.delete(SHOP);
    await egress.applyEnv(PROD);
    expect(cluster.names(PROD.namespace)).toEqual([]);
  });

  it('the egress and ingress syncs leave each other\'s policies alone', async () => {
    db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict', 'egress.default_deny': 'strict' });
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await egress.applyEnv(PROD);
    expect(cluster.names(PROD.namespace)).toEqual(['eve-egress', 'eve-egress-metadata', 'eve-ingress']);

    db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict', 'egress.default_deny': 'legacy' });
    await egress.applyEnv(PROD);
    expect(cluster.names(PROD.namespace)).toEqual(['eve-ingress']);
  });
});
