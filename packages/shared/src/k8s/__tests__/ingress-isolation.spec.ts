import { describe, expect, it } from 'vitest';
import * as k8s from '../index.js';

/**
 * network.ingress_isolation and isolation.pod_security_admission (rule set
 * 3): under strict an env namespace accepts connections only from the
 * platform's API, the project's own namespaces and runners (any pod), the
 * ingress controller (the pods of services with an ingress, on their
 * ingress port) and its app-link consumers (the producer service's pods, on
 * the link's port); under audit and legacy Eve writes no ingress policy, so
 * a project's own ingress policies are never widened. And Pod Security
 * `enforce` under strict.
 */
const api = k8s as Record<string, any>;
const NS = 'eve-acme-shop-prod';
const PEERS = {
  projectNamespaces: ['eve-acme-shop-prod', 'eve-acme-shop-staging'],
  runnerProjects: ['proj_shop'],
  routes: [{ service: 'web', port: 3000 }],
  links: [{ service: 'api', port: 8080, namespaces: ['eve-acme-portal-prod'], runnerProjects: ['proj_portal'] }],
};
const SETTINGS = { platformNamespace: 'eve', runnerNamespace: 'eve-runners' };
const name = (ns: string) => ({ matchLabels: { 'kubernetes.io/metadata.name': ns } });
const CONTROLLER = {
  namespaceSelector: { matchExpressions: [{ key: 'kubernetes.io/metadata.name', operator: 'In', values: ['traefik', 'kube-system'] }] },
  podSelector: { matchLabels: { 'app.kubernetes.io/name': 'traefik' } },
};
const runner = (ns: string, project: string) => ({
  namespaceSelector: name(ns),
  podSelector: { matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': project } },
});
const EVE_LABELS = { 'app.kubernetes.io/managed-by': 'eve-horizon', 'eve.horizon/ingress': 'env' };
const byName = (policies: any[], wanted: string) => policies.find((p: any) => p.metadata.name === wanted);

describe('envIngressPolicies', () => {
  it('under strict: eve-ingress over every pod admits only the API, the project\'s own namespaces and its runners', () => {
    const policies = api.envIngressPolicies(NS, 'strict', PEERS, SETTINGS);
    // The narrower per-service allows first, so a move to strict never refuses their callers.
    expect(policies.map((p: any) => p.metadata.name)).toEqual(['eve-ingress-svc-api', 'eve-ingress-svc-web', 'eve-ingress']);
    for (const policy of policies) {
      expect(policy.metadata.namespace).toBe(NS);
      expect(policy.metadata.labels).toEqual(EVE_LABELS);
      expect(policy.metadata.labels['eve.horizon/egress']).toBeUndefined();
      expect(policy.spec.policyTypes).toEqual(['Ingress']);
    }

    const policy = byName(policies, 'eve-ingress');
    expect(policy.spec.podSelector).toEqual({});
    expect(policy.spec.ingress).toHaveLength(1);
    expect(policy.spec.ingress[0].ports).toBeUndefined();
    const from = policy.spec.ingress[0].from;
    expect(from).toEqual(expect.arrayContaining([
      // The API alone of the platform's workloads (spec fetches, webhooks, env database queries).
      { namespaceSelector: name('eve'), podSelector: { matchExpressions: [{ key: 'app.kubernetes.io/name', operator: 'In', values: ['eve-api'] }] } },
      { namespaceSelector: name('eve-acme-shop-prod') },
      { namespaceSelector: name('eve-acme-shop-staging') },
      runner('eve-runners', 'proj_shop'),
      runner('eve', 'proj_shop'),
    ]));
    expect(from).toHaveLength(5);
    // Neither the ingress controller nor an app-link consumer reaches every pod.
    expect(from).not.toContainEqual(CONTROLLER);
    expect(from).not.toContainEqual({ namespaceSelector: name('eve-acme-portal-prod') });
    expect(from).not.toContainEqual(runner('eve-runners', 'proj_portal'));
    // Nothing that admits a whole other namespace beyond those named.
    expect(from.some((peer: any) => peer.ipBlock || (peer.namespaceSelector && Object.keys(peer.namespaceSelector).length === 0))).toBe(false);
  });

  it('admits the ingress controller only to the pods of services with an ingress, on their ingress port', () => {
    const policies = api.envIngressPolicies(NS, 'strict', PEERS, SETTINGS);
    expect(byName(policies, 'eve-ingress-svc-web').spec).toEqual({
      podSelector: { matchLabels: { 'eve.component': 'web' } },
      policyTypes: ['Ingress'],
      ingress: [{ from: [CONTROLLER], ports: [{ protocol: 'TCP', port: 3000 }] }],
    });
    const controllerRules = policies.flatMap((p: any) => p.spec.ingress.filter((rule: any) =>
      (rule.from ?? []).some((peer: any) => JSON.stringify(peer) === JSON.stringify(CONTROLLER))).map(() => p.metadata.name));
    expect(controllerRules).toEqual(['eve-ingress-svc-web']);
  });

  it('admits app-link consumers and their runners only to the producer service\'s pods, on the link\'s port', () => {
    const policies = api.envIngressPolicies(NS, 'strict', PEERS, SETTINGS);
    expect(byName(policies, 'eve-ingress-svc-api').spec).toEqual({
      podSelector: { matchLabels: { 'eve.component': 'api' } },
      policyTypes: ['Ingress'],
      ingress: [{
        from: [{ namespaceSelector: name('eve-acme-portal-prod') }, runner('eve-runners', 'proj_portal'), runner('eve', 'proj_portal')],
        ports: [{ protocol: 'TCP', port: 8080 }],
      }],
    });
  });

  it('a service with an ingress and app-link consumers gets one policy with both; a link with no known port admits its pods on any port', () => {
    const policies = api.envIngressPolicies(NS, 'strict', {
      ...PEERS,
      routes: [{ service: 'api', port: 8443 }],
      links: [{ service: 'Api_Main', port: null, namespaces: ['eve-acme-portal-prod'], runnerProjects: [] },
        { service: 'api', port: 8080, namespaces: ['eve-acme-portal-staging'], runnerProjects: [] }],
    }, SETTINGS);
    expect(policies.map((p: any) => p.metadata.name)).toEqual(['eve-ingress-svc-api', 'eve-ingress-svc-api-main', 'eve-ingress']);
    expect(byName(policies, 'eve-ingress-svc-api').spec.ingress).toEqual([
      { from: [CONTROLLER], ports: [{ protocol: 'TCP', port: 8443 }] },
      { from: [{ namespaceSelector: name('eve-acme-portal-staging') }], ports: [{ protocol: 'TCP', port: 8080 }] },
    ]);
    const main = byName(policies, 'eve-ingress-svc-api-main');
    expect(main.spec.podSelector).toEqual({ matchLabels: { 'eve.component': 'api_main' } });
    expect(main.spec.ingress).toEqual([{ from: [{ namespaceSelector: name('eve-acme-portal-prod') }] }]);
  });

  it('admits from the platform namespace only named platform workloads and the project runners, never any other pod there', () => {
    // Tenant code runs in the platform namespace too: agent runtime inline
    // jobs, the shared buildkitd, kaniko Jobs and legacy pipeline steps in
    // the worker. None of them may reach an app pod.
    expect(api.PLATFORM_INGRESS_WORKLOADS).toEqual(['eve-api']);
    const policies = api.envIngressPolicies(NS, 'strict', PEERS, SETTINGS);
    const fromPlatform = policies.flatMap((policy: any) => policy.spec.ingress.flatMap((rule: any) => rule.from ?? []))
      .filter((peer: any) => JSON.stringify(peer.namespaceSelector) === JSON.stringify(name('eve')));
    expect(fromPlatform.length).toBeGreaterThan(0);
    for (const peer of fromPlatform) {
      expect(peer.podSelector, JSON.stringify(peer)).toBeDefined();
      const expressions = peer.podSelector.matchExpressions ?? [];
      expect(expressions.every((e: any) => e.operator === 'In'), JSON.stringify(peer)).toBe(true);
      const namesWorkload = expressions.some((e: any) => e.key === 'app.kubernetes.io/name');
      const namesRunner = peer.podSelector.matchLabels?.['eve.horizon/runner'] === 'true'
        && typeof peer.podSelector.matchLabels?.['eve.horizon/project-id'] === 'string';
      expect(namesWorkload || namesRunner, JSON.stringify(peer)).toBe(true);
    }
    // Neither the worker, the agent runtime, buildkitd nor a kaniko pod.
    const workloads = fromPlatform.flatMap((peer: any) => (peer.podSelector.matchExpressions ?? []).flatMap((e: any) => e.values ?? []));
    for (const other of ['eve-worker', 'eve-agent-runtime', 'buildkitd', 'eve-orchestrator', 'eve-gateway']) {
      expect(workloads).not.toContain(other);
    }
  });

  it('under audit and legacy writes nothing: no allow-all companion beside a project\'s own policies', () => {
    expect(api.envIngressPolicies(NS, 'audit', PEERS, SETTINGS)).toEqual([]);
    expect(api.envIngressPolicies(NS, 'legacy', PEERS, SETTINGS)).toEqual([]);
  });

  it('lists each namespace and runner project once', () => {
    const policies = api.envIngressPolicies(NS, 'strict', {
      projectNamespaces: [NS, NS], runnerProjects: ['proj_shop', 'proj_shop'], routes: [{ service: 'web', port: 3000 }, { service: 'web', port: 3000 }],
      links: [{ service: 'web', port: 3000, namespaces: ['eve-acme-portal-prod', 'eve-acme-portal-prod'], runnerProjects: ['proj_portal', 'proj_portal'] }],
    }, SETTINGS);
    for (const policy of policies) {
      for (const rule of policy.spec.ingress) {
        const keys = (rule.from ?? []).map((peer: any) => JSON.stringify(peer));
        expect(new Set(keys).size, policy.metadata.name).toBe(keys.length);
        const ports = (rule.ports ?? []).map((port: any) => port.port);
        expect(new Set(ports).size, policy.metadata.name).toBe(ports.length);
      }
    }
  });
});

describe('ingressControllerRoutes', () => {
  const services = {
    web: { image: 'web', ports: [3000] },
    admin: { image: 'admin', ports: ['8080:9090'], 'x-eve': { ingress: { public: true } } },
    api: { image: 'api', ports: [8080, 9000], x_eve: { ingress: { public: true, port: 9000 } } },
    auth: { image: 'auth', ports: [9999], 'x-eve': { ingress: { public: false } } },
    queue: { image: 'queue' },
    migrate: { image: 'migrate', ports: [5000], 'x-eve': { role: 'job' } },
    db: { 'x-eve': { role: 'managed_db' } },
    billing: { ports: [7000], 'x-eve': { external: true } },
  };

  it('names the services the deployer gives an ingress, with the port it routes to (x-eve.ingress.port, else the first port)', () => {
    expect(api.ingressControllerRoutes(services, 'legacy')).toEqual([
      { service: 'web', port: 3000 },
      { service: 'admin', port: 9090 },
      { service: 'api', port: 9000 },
    ]);
  });

  it('follows ports.implicit_public: under its strict profile a service with ports and no ingress block has none', () => {
    expect(api.ingressControllerRoutes(services, 'strict')).toEqual([
      { service: 'admin', port: 9090 },
      { service: 'api', port: 9000 },
    ]);
    expect(api.ingressControllerRoutes(null, 'legacy')).toEqual([]);
  });
});

describe('podSecurityAdmissionPatch', () => {
  const MARK = 'eve.horizon/pod-security-enforce';
  const PSA = 'pod-security.kubernetes.io';
  const none = { labels: {}, annotations: {} };
  const patch = (input: Record<string, unknown>) => api.podSecurityAdmissionPatch({ current: none, ...input });

  it('lowers only an enforce Eve set that is stricter than the level (podSecurityEnforceLowering, also used before a service job)', () => {
    const marked = { labels: { [`${PSA}/enforce`]: 'restricted' }, annotations: { [MARK]: 'restricted' } };
    expect(api.podSecurityEnforceLowering(marked, 'baseline')).toEqual({
      labels: { [`${PSA}/enforce`]: 'baseline' }, annotations: { [MARK]: 'baseline' },
    });
    expect(api.podSecurityEnforceLowering(marked, 'restricted')).toEqual(none);
    expect(api.podSecurityEnforceLowering({ labels: marked.labels, annotations: {} }, 'baseline')).toEqual(none);
    expect(api.podSecurityEnforceLowering(none, 'baseline')).toEqual(none);
  });

  it('under strict, before the workloads: warn and audit only, never a new enforce', () => {
    expect(patch({ profile: 'strict', level: 'restricted', phase: 'before' })).toEqual({
      labels: { [`${PSA}/warn`]: 'restricted', [`${PSA}/audit`]: 'restricted' },
      annotations: {},
    });
  });

  it('under strict, after a rollout that succeeded: enforce at the level, pinned to a version (not latest), marked as set by Eve', () => {
    const after = patch({ profile: 'strict', level: 'baseline', phase: 'after' });
    expect(after.labels).toEqual({
      [`${PSA}/enforce`]: 'baseline',
      [`${PSA}/enforce-version`]: api.DEFAULT_POD_SECURITY_VERSION,
      [`${PSA}/warn`]: 'baseline',
      [`${PSA}/audit`]: 'baseline',
    });
    expect(api.DEFAULT_POD_SECURITY_VERSION).toMatch(/^v1\.\d+$/);
    expect(after.annotations).toEqual({ [MARK]: 'baseline' });
    expect(patch({ profile: 'strict', level: 'restricted', phase: 'after', version: 'v1.31' }).labels[`${PSA}/enforce-version`]).toBe('v1.31');
  });

  it('writes only what differs', () => {
    const current = {
      labels: { [`${PSA}/enforce`]: 'restricted', [`${PSA}/enforce-version`]: 'v1.30', [`${PSA}/warn`]: 'restricted', [`${PSA}/audit`]: 'restricted' },
      annotations: { [MARK]: 'restricted' },
    };
    expect(patch({ profile: 'strict', level: 'restricted', phase: 'after', version: 'v1.30', current })).toEqual({ labels: {}, annotations: {} });
    expect(patch({ profile: 'strict', level: 'restricted', phase: 'before', current })).toEqual({ labels: {}, annotations: {} });
  });

  it('under strict, before the workloads, lowers an enforce Eve set when the level drops, so the new pods are admitted', () => {
    const current = { labels: { [`${PSA}/enforce`]: 'restricted', [`${PSA}/enforce-version`]: 'v1.30' }, annotations: { [MARK]: 'restricted' } };
    expect(patch({ profile: 'strict', level: 'baseline', phase: 'before', current })).toEqual({
      labels: { [`${PSA}/enforce`]: 'baseline', [`${PSA}/warn`]: 'baseline', [`${PSA}/audit`]: 'baseline' },
      annotations: { [MARK]: 'baseline' },
    });
  });

  it('under audit and legacy removes an enforce Eve set, with its version and mark, and leaves one it did not set', () => {
    const eves = { labels: { [`${PSA}/enforce`]: 'restricted', [`${PSA}/enforce-version`]: 'v1.30' }, annotations: { [MARK]: 'restricted' } };
    const operators = { labels: { [`${PSA}/enforce`]: 'baseline', [`${PSA}/enforce-version`]: 'v1.29' }, annotations: {} };
    expect(patch({ profile: 'audit', level: 'restricted', phase: 'before', current: eves })).toEqual({
      labels: { [`${PSA}/enforce`]: null, [`${PSA}/enforce-version`]: null, [`${PSA}/warn`]: 'restricted', [`${PSA}/audit`]: 'restricted' },
      annotations: { [MARK]: null },
    });
    expect(patch({ profile: 'legacy', level: 'restricted', phase: 'before', current: eves })).toEqual({
      labels: { [`${PSA}/enforce`]: null, [`${PSA}/enforce-version`]: null },
      annotations: { [MARK]: null },
    });
    expect(patch({ profile: 'legacy', level: 'restricted', phase: 'before', current: operators })).toEqual({ labels: {}, annotations: {} });
    expect(patch({ profile: 'audit', level: 'restricted', phase: 'before', current: operators }).labels[`${PSA}/enforce`]).toBeUndefined();
  });

  it('after the rollout changes nothing under audit and legacy', () => {
    expect(patch({ profile: 'audit', level: 'restricted', phase: 'after' })).toEqual({ labels: {}, annotations: {} });
    expect(patch({ profile: 'legacy', level: 'restricted', phase: 'after' })).toEqual({ labels: {}, annotations: {} });
  });
});
