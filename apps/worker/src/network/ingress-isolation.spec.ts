import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EgressPolicies } from './egress-policies.js';

/**
 * network.ingress_isolation in the worker: under strict each env namespace
 * gets `eve-ingress` (the project's own env namespaces and runners, any pod)
 * and one `eve-ingress-svc-<service>` per service the ingress controller
 * routes to or app-link consumers call (those callers, that service's pods
 * and port), from the database and the env's manifest. Under audit and
 * legacy Eve writes none, so a project's own ingress policies are never
 * widened, and audit records what strict would write. The egress sync and
 * the ingress sync each delete only their own policies.
 */
import { decideSecurityRule } from '@eve/db';
const db = vi.hoisted(() => ({
  profiles: new Map<string, Record<string, 'legacy' | 'audit' | 'strict'>>(),
  projects: new Map<string, { id: string; org_id: string; slug: string; repo_url: string | null }>(),
  orgs: new Map<string, { id: string; slug: string }>(),
  envs: [] as Array<Record<string, any>>,
  subscriptions: [] as Array<Record<string, any>>,
  manifests: new Map<string, string>(),
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
    findLatestSyncedByProject: async (projectId: string) =>
      (db.manifests.has(projectId) ? { manifest_yaml: db.manifests.get(projectId) } : null),
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

// The shop's web is public; its api is private and app-linked; its auth is
// private and called by its own pods only (the project restricts it itself).
const SHOP_MANIFEST = `
services:
  web:
    image: web
    ports: [3000]
    x-eve:
      ingress:
        public: true
  api:
    image: api
    ports: [8080]
    x-eve:
      ingress:
        public: false
  auth:
    image: auth
    ports: [9999]
    x-eve:
      ingress:
        public: false
`;
const SHOP = 'proj_shop';
const PORTAL = 'proj_portal';
const PROD = { id: 'env_prod', projectId: SHOP, name: 'prod', namespace: 'eve-acme-shop-prod' };
const nsPeer = (ns: string) => ({ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': ns } } });
const runnerPeer = (ns: string, project: string) => ({
  namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': ns } },
  podSelector: { matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': project } },
});
const CONTROLLER = {
  namespaceSelector: { matchExpressions: [{ key: 'kubernetes.io/metadata.name', operator: 'In', values: ['traefik', 'kube-system'] }] },
  podSelector: { matchLabels: { 'app.kubernetes.io/name': 'traefik' } },
};
const component = (name: string) => ({ matchLabels: { 'eve.component': name } });
/** A project's own NetworkPolicy, as a tenant writes it: no Eve labels. */
const tenantPolicy = (namespace: string) => ({
  metadata: { name: 'auth-from-web-only', namespace, labels: { app: 'auth' } },
  spec: { podSelector: component('auth'), policyTypes: ['Ingress'], ingress: [{ from: [{ podSelector: component('web') }] }] },
});

function egressFor(cluster: ReturnType<typeof fakeCluster>) {
  return new EgressPolicies({} as never, cluster.api as never, { logger: { log: vi.fn(), warn: vi.fn() }, resolveHost: async () => [] });
}

beforeEach(() => {
  vi.unstubAllEnvs();
  vi.stubEnv('EVE_RUNNER_NAMESPACE', 'eve-runners');
  vi.stubEnv('EVE_K8S_NAMESPACE', 'eve');
  vi.mocked(decideSecurityRule).mockClear();
  db.profiles = new Map();
  db.manifests = new Map([[SHOP, SHOP_MANIFEST]]);
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
  it('under strict: eve-ingress admits the project, its runners and the API to every pod; consumers and the controller only their service', async () => {
    db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict' });
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    await egressFor(cluster).applyEnv(PROD);

    expect(cluster.names(PROD.namespace)).toEqual(['eve-ingress', 'eve-ingress-svc-api', 'eve-ingress-svc-web']);
    const from = cluster.get(PROD.namespace, 'eve-ingress')!.spec.ingress[0].from;
    expect(from).toEqual(expect.arrayContaining([
      nsPeer('eve-acme-shop-prod'), nsPeer('eve-acme-shop-staging'), runnerPeer('eve-runners', SHOP), runnerPeer('eve', SHOP),
    ]));
    for (const wider of [CONTROLLER, nsPeer('eve-acme-portal-prod'), runnerPeer('eve-runners', PORTAL), runnerPeer('eve', PORTAL)]) {
      expect(from).not.toContainEqual(wider);
    }

    // The portal (a live `same` link to api) reaches the api pods on the api port, and nothing else.
    expect(cluster.get(PROD.namespace, 'eve-ingress-svc-api')!.spec).toEqual({
      podSelector: component('api'),
      policyTypes: ['Ingress'],
      ingress: [{
        from: [nsPeer('eve-acme-portal-prod'), runnerPeer('eve-runners', PORTAL), runnerPeer('eve', PORTAL)],
        ports: [{ protocol: 'TCP', port: 8080 }],
      }],
    });
    // The ingress controller reaches the public web pods on their port, and nothing else.
    expect(cluster.get(PROD.namespace, 'eve-ingress-svc-web')!.spec).toEqual({
      podSelector: component('web'),
      policyTypes: ['Ingress'],
      ingress: [{ from: [CONTROLLER], ports: [{ protocol: 'TCP', port: 3000 }] }],
    });
    // A revoked grant, and another env of the consumer, count for nothing.
    const all = JSON.stringify([...cluster.store.values()]);
    expect(all).not.toContain('eve-acme-other-prod');
    expect(all).not.toContain('eve-acme-portal-staging');
    expect(all).not.toContain('proj_other');
  });

  it('a fixed-env consumer: every env namespace of the consumer may call that producer env\'s service', async () => {
    db.subscriptions = [{ consumer_project_id: PORTAL, environment_strategy: 'fixed', producer_env_name: 'prod',
      api_grant: { producer_project_id: SHOP, service_name: 'api', envs: [], revoked_at: null } }];
    db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict' });
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    await egressFor(cluster).applyEnv(PROD);
    const api = cluster.get(PROD.namespace, 'eve-ingress-svc-api')!.spec.ingress[0].from;
    expect(api).toEqual(expect.arrayContaining([nsPeer('eve-acme-portal-prod'), nsPeer('eve-acme-portal-staging')]));

    // The shop's staging env is not that producer env: the portal may not call it.
    await egressFor(cluster).applyEnv({ id: 'env_staging', projectId: SHOP, name: 'staging', namespace: 'eve-acme-shop-staging' });
    expect(cluster.names('eve-acme-shop-staging')).toEqual(['eve-ingress', 'eve-ingress-svc-web']);
    const staging = JSON.stringify(cluster.get('eve-acme-shop-staging', 'eve-ingress')!.spec);
    expect(staging).not.toContain('eve-acme-portal');
    expect(staging).not.toContain(PORTAL);
    expect(cluster.get('eve-acme-shop-staging', 'eve-ingress')!.spec.ingress[0].from).toContainEqual(nsPeer('eve-acme-shop-prod'));
  });

  it('under audit writes no ingress policy, so a project\'s own policies stand, and records what strict would write', async () => {
    db.profiles.set(SHOP, { 'network.ingress_isolation': 'audit' });
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    await cluster.api.applyNetworkPolicy(tenantPolicy(PROD.namespace));
    cluster.writes.length = 0;
    await egressFor(cluster).applyEnv(PROD);

    expect(cluster.writes).toEqual([]);
    expect(cluster.names(PROD.namespace)).toEqual(['auth-from-web-only']);
    expect(vi.mocked(decideSecurityRule)).toHaveBeenCalledWith(expect.anything(), 'network.ingress_isolation', expect.objectContaining({
      projectId: SHOP,
      governing: 'project',
      detail: expect.objectContaining({
        scope: 'env', env: 'prod', enforced: false, policies: 'eve-ingress-svc-api,eve-ingress-svc-web,eve-ingress',
      }),
    }));
  });

  it('a move from strict to audit or legacy removes Eve\'s ingress policies, and only those', async () => {
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await cluster.api.applyNetworkPolicy(tenantPolicy(PROD.namespace));
    // An allow-all companion a pre-release build wrote under audit.
    await cluster.api.applyNetworkPolicy({
      metadata: { name: 'eve-ingress-audit', namespace: PROD.namespace,
        labels: { 'app.kubernetes.io/managed-by': 'eve-horizon', 'eve.horizon/ingress': 'env' } },
      spec: { podSelector: {}, policyTypes: ['Ingress'], ingress: [{}] },
    });

    for (const next of ['audit', 'legacy'] as const) {
      db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict' });
      await egress.applyEnv(PROD);
      expect(cluster.names(PROD.namespace)).toEqual(['auth-from-web-only', 'eve-ingress', 'eve-ingress-svc-api', 'eve-ingress-svc-web']);

      db.profiles.set(SHOP, { 'network.ingress_isolation': next });
      const synced = await egress.applyEnv(PROD);
      expect(cluster.names(PROD.namespace), next).toEqual(['auth-from-web-only']);
      expect(synced.removed.sort(), next).toEqual(['eve-ingress', 'eve-ingress-svc-api', 'eve-ingress-svc-web']);
    }
  });

  it('the egress and ingress syncs leave each other\'s policies alone', async () => {
    db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict', 'egress.default_deny': 'strict' });
    const cluster = fakeCluster([PROD.namespace, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await egress.applyEnv(PROD);
    expect(cluster.names(PROD.namespace)).toEqual([
      'eve-egress', 'eve-egress-metadata', 'eve-ingress', 'eve-ingress-svc-api', 'eve-ingress-svc-web',
    ]);

    db.profiles.set(SHOP, { 'network.ingress_isolation': 'strict', 'egress.default_deny': 'legacy' });
    await egress.applyEnv(PROD);
    expect(cluster.names(PROD.namespace)).toEqual(['eve-ingress', 'eve-ingress-svc-api', 'eve-ingress-svc-web']);
  });
});
