import { beforeEach, describe, expect, it, vi } from 'vitest';
import { EgressPolicies } from './egress-policies.js';

/**
 * egress.allow_hosts in the worker: with EVE_EGRESS_FQDN_PROVIDER=gke it
 * writes one GKE FQDNNetworkPolicy per declared host (env namespaces from the
 * release's manifest, runner namespaces from the project's manifest, its
 * harness hosts and its git host) and prunes Eve's own; under strict the
 * internet rule goes; with no provider a strict project is refused. The
 * Kubernetes API is an in-memory fake.
 */
const db = vi.hoisted(() => ({
  profiles: new Map<string, Record<string, 'legacy' | 'audit' | 'strict'>>(),
  findings: [] as Array<{ rule: string; projectId: string; detail: Record<string, unknown> }>,
  projects: new Map<string, { id: string; org_id: string; slug: string; repo_url: string | null }>(),
  orgs: new Map<string, { id: string; slug: string }>(),
  envs: [] as Array<Record<string, any>>,
  manifests: new Map<string, string>(),
  releaseManifests: new Map<string, string>(),
}));

const profileOf = (projectId: string, rule: string) => db.profiles.get(projectId)?.[rule] ?? 'legacy';

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  governingSecurityProfile: vi.fn(async (_db: unknown, ctx: { projectId: string; rule: string }) => profileOf(ctx.projectId, ctx.rule)),
  decideSecurityRule: vi.fn(async (_db: unknown, rule: string, ctx: { projectId: string; detail?: Record<string, unknown> }) => {
    const profile = profileOf(ctx.projectId, rule);
    if (profile !== 'legacy') db.findings.push({ rule, projectId: ctx.projectId, detail: ctx.detail ?? {} });
    return profile;
  }),
  systemSettingsQueries: () => ({ get: async () => null }),
  projectQueries: () => ({ findById: async (id: string) => db.projects.get(id) ?? null }),
  orgQueries: () => ({ findById: async (id: string) => db.orgs.get(id) ?? null }),
  environmentQueries: () => ({
    listByProject: async (projectId: string) => db.envs.filter((e) => e.project_id === projectId),
    findByProjectAndName: async (projectId: string, name: string) =>
      db.envs.find((e) => e.project_id === projectId && e.name === name) ?? null,
    findById: async (id: string) => db.envs.find((e) => e.id === id) ?? null,
  }),
  releaseQueries: () => ({
    findById: async (id: string) => (db.releaseManifests.has(id) ? { id, manifest_hash: `hash-${id}` } : null),
  }),
  managedDbQueries: () => ({ listTenantsByEnv: async () => [], findInstanceById: async () => null }),
  appLinkSubscriptionQueries: () => ({ listWithGrants: async () => [] }),
  projectManifestQueries: () => ({
    findLatestByProject: async (projectId: string) =>
      (db.manifests.has(projectId) ? { manifest_yaml: db.manifests.get(projectId) } : null),
    findByProjectAndHash: async (_projectId: string, hash: string) => {
      const id = hash.replace(/^hash-/, '');
      return db.releaseManifests.has(id) ? { manifest_yaml: db.releaseManifests.get(id) } : null;
    },
  }),
  securityQueries: () => ({
    listProjectProfiles: async (scope: { projectId?: string }) =>
      [...db.projects.values()]
        .filter((p) => (scope.projectId ? p.id === scope.projectId : true))
        .map((p) => ({ id: p.id, slug: p.slug, org_id: p.org_id, security_profile: null })),
  }),
}));

type Obj = { kind?: string; metadata: { name: string; namespace: string; labels: Record<string, string>; annotations?: Record<string, string> }; spec: any };

/** An in-memory cluster holding NetworkPolicies and FQDNNetworkPolicies. */
function fakeCluster(namespaces: string[]) {
  const nsSet = new Set(namespaces);
  const nps = new Map<string, Obj>();
  const fqdns = new Map<string, Obj>();
  const log: string[] = [];
  const key = (ns: string, name: string) => `${ns}/${name}`;
  const select = (store: Map<string, Obj>, namespace: string, selector: string) => {
    const wanted = selector.split(',').map((s) => s.split('='));
    return [...store.values()]
      .filter((p) => p.metadata.namespace === namespace)
      .filter((p) => wanted.every(([k, v]) => p.metadata.labels?.[k] === v))
      .map((p) => ({ name: p.metadata.name, labels: p.metadata.labels }));
  };
  const write = (store: Map<string, Obj>, tag: string) => vi.fn(async (obj: Obj) => {
    const { namespace, name } = obj.metadata;
    if (!nsSet.has(namespace)) throw Object.assign(new Error(`namespaces "${namespace}" not found`), { statusCode: 404 });
    const existing = store.get(key(namespace, name));
    if (existing && JSON.stringify(existing) === JSON.stringify(obj)) return false;
    store.set(key(namespace, name), JSON.parse(JSON.stringify(obj)));
    log.push(`${tag}:apply:${namespace}/${name}`);
    return true;
  });
  const remove = (store: Map<string, Obj>, tag: string) => vi.fn(async (namespace: string, name: string) => {
    store.delete(key(namespace, name));
    log.push(`${tag}:delete:${namespace}/${name}`);
  });
  const api = {
    getNamespaceLabels: vi.fn(async (name: string) => (nsSet.has(name) ? {} : null)),
    applyNetworkPolicy: write(nps, 'np'),
    deleteNetworkPolicy: remove(nps, 'np'),
    listNetworkPolicies: vi.fn(async (namespace: string, selector: string) => select(nps, namespace, selector)),
    applyFqdnNetworkPolicy: write(fqdns, 'fqdn'),
    deleteFqdnNetworkPolicy: remove(fqdns, 'fqdn'),
    listFqdnNetworkPolicies: vi.fn(async (namespace: string, selector: string) => select(fqdns, namespace, selector)),
  };
  const fqdnHosts = (namespace: string) => [...fqdns.values()]
    .filter((p) => p.metadata.namespace === namespace)
    .map((p) => {
      const match = p.spec.egress[0].matches[0];
      return `${match.name ?? match.pattern}:${p.spec.egress[0].ports[0].port}`;
    })
    .sort();
  const fqdnSelectors = (namespace: string) => Object.fromEntries([...fqdns.values()]
    .filter((p) => p.metadata.namespace === namespace)
    .map((p) => [p.spec.egress[0].matches[0].name ?? p.spec.egress[0].matches[0].pattern, p.spec.podSelector]));
  const np = (namespace: string, name: string) => nps.get(key(namespace, name));
  const npNames = (namespace: string) => [...nps.values()].filter((p) => p.metadata.namespace === namespace).map((p) => p.metadata.name).sort();
  return { api, nps, fqdns, log, fqdnHosts, fqdnSelectors, np, npNames };
}

const SHOP = 'proj_shop';
const NS = 'eve-acme-shop-prod';
const PROD = { id: 'env_prod', projectId: SHOP, name: 'prod', namespace: NS };
const MANIFEST = [
  'x-eve:',
  '  egress:',
  '    hosts: [api.example.com, "*.cdn.example.com"]',
  'services:',
  '  web:',
  '    image: web:1',
  '    x-eve:',
  '      egress:',
  '        hosts: [{ name: smtp.example.com, port: 587 }]',
  '',
].join('\n');

const hasInternet = (policy: Obj | undefined) =>
  (policy?.spec.egress ?? []).some((rule: any) => (rule.to ?? []).some((peer: any) => peer.ipBlock?.cidr === '0.0.0.0/0'));

function egressFor(cluster: ReturnType<typeof fakeCluster>) {
  const logger = { log: vi.fn(), warn: vi.fn() };
  return new EgressPolicies({} as never, cluster.api as never, { logger, resolveHost: async () => [] });
}

beforeEach(() => {
  vi.unstubAllEnvs();
  vi.stubEnv('EVE_RUNNER_NAMESPACE', 'eve-runners');
  vi.stubEnv('EVE_K8S_NAMESPACE', 'eve');
  db.profiles = new Map();
  db.findings = [];
  db.projects = new Map([[SHOP, { id: SHOP, org_id: 'org_acme', slug: 'shop', repo_url: 'https://github.com/acme/shop.git' }]]);
  db.orgs = new Map([['org_acme', { id: 'org_acme', slug: 'acme' }]]);
  db.envs = [{ id: 'env_prod', project_id: SHOP, name: 'prod', namespace: null, status: 'active', last_applied_release_id: 'rel_1', current_release_id: 'rel_1' }];
  db.manifests = new Map([[SHOP, MANIFEST]]);
  db.releaseManifests = new Map([['rel_1', MANIFEST]]);
});

const strict = () => db.profiles.set(SHOP, { 'egress.default_deny': 'strict', 'egress.allow_hosts': 'strict' });
const audit = () => db.profiles.set(SHOP, { 'egress.default_deny': 'audit', 'egress.allow_hosts': 'audit' });

describe('provider none', () => {
  it('refuses a strict project at deploy and dispatch, naming the provider, and writes nothing', async () => {
    strict();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);

    await expect(egress.applyEnv(PROD)).rejects.toThrow('egress allow lists need a provider (EVE_EGRESS_FQDN_PROVIDER)');
    await expect(egress.ensureRunnersForDispatch(SHOP)).rejects.toThrow('egress allow lists need a provider (EVE_EGRESS_FQDN_PROVIDER)');
    await expect(egress.applyRunners(SHOP)).rejects.toThrow(/EVE_EGRESS_FQDN_PROVIDER/);
    expect(cluster.log).toEqual([]);
    expect(cluster.api.listFqdnNetworkPolicies).not.toHaveBeenCalled();
  });

  it('under audit writes the NetworkPolicies as before and touches no FQDN policy', async () => {
    audit();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    await egressFor(cluster).applyEnv(PROD);
    expect(cluster.npNames(NS)).toEqual(['eve-egress', 'eve-egress-audit', 'eve-egress-metadata']);
    expect(cluster.fqdns.size).toBe(0);
    expect(cluster.api.listFqdnNetworkPolicies).not.toHaveBeenCalled();
  });

  it('under legacy changes nothing', async () => {
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    await egressFor(cluster).applyEnv(PROD);
    expect(cluster.log).toEqual([]);
  });
});

describe('provider gke', () => {
  beforeEach(() => { vi.stubEnv('EVE_EGRESS_FQDN_PROVIDER', 'gke'); });

  it('under strict writes the NetworkPolicies first, then one FQDN policy per host', async () => {
    strict();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    await egressFor(cluster).applyEnv(PROD);

    expect(cluster.fqdnHosts(NS)).toEqual(['*.cdn.example.com:443', 'api.example.com:443', 'smtp.example.com:587']);
    expect(cluster.fqdnSelectors(NS)).toEqual({
      'api.example.com': {},
      '*.cdn.example.com': {},
      'smtp.example.com': { matchLabels: { 'eve.component': 'web' } },
    });
    expect(cluster.npNames(NS)).toEqual(['eve-egress', 'eve-egress-metadata']);
    expect(hasInternet(cluster.np(NS, 'eve-egress'))).toBe(false);
    // A failed FQDN write must never leave an older, wider NetworkPolicy in place.
    const firstFqdn = cluster.log.findIndex((entry) => entry.startsWith('fqdn:apply'));
    const egressWrite = cluster.log.indexOf(`np:apply:${NS}/eve-egress`);
    expect(egressWrite).toBeGreaterThanOrEqual(0);
    expect(egressWrite).toBeLessThan(firstFqdn);
  });

  it('under audit (a rule set 2 stamp beside a strict default deny) a failed FQDN write is recorded and blocks nothing', async () => {
    db.profiles.set(SHOP, { 'egress.default_deny': 'strict', 'egress.allow_hosts': 'audit' });
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const missingCrd = Object.assign(new Error('the server could not find the requested resource'), { statusCode: 404 });
    cluster.api.applyFqdnNetworkPolicy.mockRejectedValue(missingCrd);
    const egress = egressFor(cluster);

    await expect(egress.applyEnv(PROD)).resolves.toBeDefined();
    expect(cluster.npNames(NS)).toEqual(['eve-egress', 'eve-egress-metadata']);
    await expect(egress.applyRunners(SHOP)).resolves.toBeDefined();
    await expect(egress.ensureRunnersForDispatch(SHOP)).resolves.toBeDefined();
    expect(cluster.npNames('eve-runners')).toEqual([expect.stringMatching(/^eve-runner-/)]);
    expect(db.findings).toEqual(expect.arrayContaining([expect.objectContaining({
      rule: 'egress.allow_hosts',
      detail: expect.objectContaining({ reason: 'fqdn_write_failed', scope: 'env', env: 'prod' }),
    }), expect.objectContaining({
      rule: 'egress.allow_hosts',
      detail: expect.objectContaining({ reason: 'fqdn_write_failed', scope: 'runner' }),
    })]));
  });

  it('under strict a failed FQDN write leaves the runners no internet rule and refuses the job', async () => {
    audit();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await egress.applyRunners(SHOP);
    expect(cluster.npNames('eve-runners').some((name) => name.endsWith('-audit'))).toBe(true);

    strict();
    cluster.api.applyFqdnNetworkPolicy.mockRejectedValue(new Error('admission webhook denied the request'));
    const refusal = await egress.ensureRunnersForDispatch(SHOP).then(() => null, (error: Error) => error);
    expect(refusal).toBeInstanceOf(Error);
    expect(refusal!.name).toBe('RunnerEgressSyncError');
    expect(refusal!.message).toMatch(/proj_shop/);
    expect(refusal!.message).toMatch(/admission webhook denied the request/);
    for (const namespace of ['eve-runners', 'eve']) {
      expect(cluster.npNames(namespace).some((name) => name.endsWith('-audit'))).toBe(false);
      for (const name of cluster.npNames(namespace)) expect(hasInternet(cluster.np(namespace, name))).toBe(false);
    }
  });

  it('under strict refuses the job when the runner NetworkPolicies cannot be written', async () => {
    strict();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    cluster.api.applyNetworkPolicy.mockRejectedValue(new Error('networkpolicies is forbidden'));
    const refusal = await egressFor(cluster).ensureRunnersForDispatch(SHOP).then(() => null, (error: Error) => error);
    expect(refusal?.name).toBe('RunnerEgressSyncError');
    expect(refusal?.message).toMatch(/networkpolicies is forbidden/);
  });

  it('at dispatch rewrites a runner policy whose content changed under the same name (egress.allow_hosts audit to strict)', async () => {
    db.profiles.set(SHOP, { 'egress.default_deny': 'strict', 'egress.allow_hosts': 'audit' });
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await expect(egress.ensureRunnersForDispatch(SHOP)).resolves.toBe('written');
    await expect(egress.ensureRunnersForDispatch(SHOP)).resolves.toBe('current');
    const [name] = cluster.npNames('eve-runners');
    expect(hasInternet(cluster.np('eve-runners', name))).toBe(true);

    strict();
    await expect(egress.ensureRunnersForDispatch(SHOP)).resolves.toBe('written');
    expect(cluster.npNames('eve-runners')).toEqual([name]);
    expect(hasInternet(cluster.np('eve-runners', name))).toBe(false);
    await expect(egress.ensureRunnersForDispatch(SHOP)).resolves.toBe('current');
  });

  it('takes the hosts of the manifest passed at deploy over the stored release', async () => {
    strict();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    await egressFor(cluster).applyEnv(PROD, 'strict', { allowHosts: 'strict', manifest: { 'x-eve': { egress: { hosts: ['hooks.example.com'] } } } });
    expect(cluster.fqdnHosts(NS)).toEqual(['hooks.example.com:443']);
  });

  it('writes runner policies from the project list, every harness host and the git host, selecting the project label', async () => {
    strict();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    await egressFor(cluster).applyRunners(SHOP);

    for (const namespace of ['eve-runners', 'eve']) {
      const listed = cluster.fqdnHosts(namespace);
      expect(listed).toEqual(expect.arrayContaining([
        'api.example.com:443', '*.cdn.example.com:443', 'github.com:443', 'api.anthropic.com:443', 'api.openai.com:443',
      ]));
      expect(listed).not.toContain('smtp.example.com:587');
      for (const selector of Object.values(cluster.fqdnSelectors(namespace))) {
        expect(selector).toEqual({ matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': SHOP } });
      }
    }
    const runnerPolicy = [...cluster.nps.values()].find((p) => p.metadata.namespace === 'eve-runners')!;
    expect(hasInternet(runnerPolicy)).toBe(false);
  });

  it('prunes the policy of a host the manifest drops, leaving FQDN policies Eve did not write', async () => {
    strict();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    cluster.fqdns.set(`${NS}/hand-made`, {
      metadata: { name: 'hand-made', namespace: NS, labels: {} },
      spec: { podSelector: {}, egress: [{ matches: [{ name: 'own.example.com' }], ports: [{ protocol: 'TCP', port: 443 }] }] },
    });
    const egress = egressFor(cluster);
    await egress.applyEnv(PROD);
    db.releaseManifests.set('rel_1', 'x-eve:\n  egress:\n    hosts: [api.example.com]\n');
    await egress.applyEnv(PROD);

    expect(cluster.fqdnHosts(NS)).toEqual(['api.example.com:443', 'own.example.com:443']);
    expect(cluster.log.filter((entry) => entry.startsWith('fqdn:delete'))).toHaveLength(2);
  });

  it('under audit writes the FQDN policies beside the companions, so nothing is blocked', async () => {
    audit();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await egress.applyEnv(PROD);
    await egress.applyRunners(SHOP);

    expect(cluster.fqdnHosts(NS)).toHaveLength(3);
    expect(cluster.npNames(NS)).toContain('eve-egress-audit');
    expect(hasInternet(cluster.np(NS, 'eve-egress'))).toBe(true);
    expect(cluster.npNames('eve-runners').some((name) => name.endsWith('-audit'))).toBe(true);
    expect(cluster.fqdnHosts('eve-runners').length).toBeGreaterThan(3);
  });

  it('records a finding for a project that declares no hosts, and none for one that does', async () => {
    audit();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await egress.applyEnv(PROD);
    expect(db.findings.filter((f) => f.rule === 'egress.allow_hosts')).toEqual([]);

    db.releaseManifests.set('rel_1', 'services:\n  web:\n    image: web:1\n');
    await egress.applyEnv(PROD);
    expect(db.findings).toEqual([expect.objectContaining({
      rule: 'egress.allow_hosts',
      projectId: SHOP,
      detail: expect.objectContaining({ reason: 'no_declared_hosts', env: 'prod' }),
    })]);
  });

  it('under legacy removes the FQDN policies Eve wrote', async () => {
    audit();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await egress.applyEnv(PROD);
    await egress.applyRunners(SHOP);
    db.profiles.delete(SHOP);
    await egress.applyEnv(PROD);
    await egress.applyRunners(SHOP);
    expect(cluster.fqdns.size).toBe(0);
  });

  it('at dispatch writes the runner policies once, and again when the declared hosts change', async () => {
    strict();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await expect(egress.ensureRunnersForDispatch(SHOP)).resolves.toBe('written');
    await expect(egress.ensureRunnersForDispatch(SHOP)).resolves.toBe('current');
    db.manifests.set(SHOP, 'x-eve:\n  egress:\n    hosts: [api.example.com, hooks.example.com]\n');
    await expect(egress.ensureRunnersForDispatch(SHOP)).resolves.toBe('written');
    expect(cluster.fqdnHosts('eve-runners')).toContain('hooks.example.com:443');
    expect(cluster.fqdnHosts('eve-runners')).not.toContain('*.cdn.example.com:443');
  });

  it('reconcile removes the runner FQDN policies of a deleted project', async () => {
    audit();
    const cluster = fakeCluster([NS, 'eve-runners', 'eve']);
    const egress = egressFor(cluster);
    await egress.applyRunners(SHOP);
    expect(cluster.fqdnHosts('eve-runners').length).toBeGreaterThan(0);
    db.projects.delete(SHOP);
    const report = await egress.reconcile();
    expect(cluster.fqdnHosts('eve-runners')).toEqual([]);
    expect(cluster.fqdnHosts('eve')).toEqual([]);
    expect(report.runners.orphans_removed).toBeGreaterThan(0);
  });
});
