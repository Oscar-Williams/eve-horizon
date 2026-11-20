import { describe, expect, it } from 'vitest';
import * as k8s from '../index.js';

/**
 * network.ingress_isolation and isolation.pod_security_admission (rule set
 * 3): an env namespace accepts connections only from the ingress
 * controller, the platform's services, the project's own namespaces and
 * runners, and its app-link consumers; and carries Pod Security `enforce`
 * under strict.
 */
const api = k8s as Record<string, any>;
const NS = 'eve-acme-shop-prod';
const PEERS = {
  projectNamespaces: ['eve-acme-shop-prod', 'eve-acme-shop-staging'],
  consumerNamespaces: ['eve-acme-portal-prod'],
  runnerProjects: ['proj_shop', 'proj_portal'],
};
const SETTINGS = { platformNamespace: 'eve', runnerNamespace: 'eve-runners' };
const name = (ns: string) => ({ matchLabels: { 'kubernetes.io/metadata.name': ns } });

describe('envIngressPolicies', () => {
  it('under strict: one policy over every pod, allowing only the listed sources, on any port', () => {
    const policies = api.envIngressPolicies(NS, 'strict', PEERS, SETTINGS);
    expect(policies.map((p: any) => p.metadata.name)).toEqual(['eve-ingress']);
    const [policy] = policies;
    expect(policy.metadata.namespace).toBe(NS);
    expect(policy.metadata.labels).toEqual({ 'app.kubernetes.io/managed-by': 'eve-horizon', 'eve.horizon/ingress': 'env' });
    expect(policy.metadata.labels['eve.horizon/egress']).toBeUndefined();
    expect(policy.spec.podSelector).toEqual({});
    expect(policy.spec.policyTypes).toEqual(['Ingress']);
    expect(policy.spec.ingress).toHaveLength(1);
    expect(policy.spec.ingress[0].ports).toBeUndefined();

    const from = policy.spec.ingress[0].from;
    expect(from).toEqual(expect.arrayContaining([
      // The ingress controller (Traefik), as egress-policies.ts names it.
      {
        namespaceSelector: { matchExpressions: [{ key: 'kubernetes.io/metadata.name', operator: 'In', values: ['traefik', 'kube-system'] }] },
        podSelector: { matchLabels: { 'app.kubernetes.io/name': 'traefik' } },
      },
      // The API alone of the platform's workloads (spec fetches, webhooks, env database queries).
      { namespaceSelector: name('eve'), podSelector: { matchExpressions: [{ key: 'app.kubernetes.io/name', operator: 'In', values: ['eve-api'] }] } },
      { namespaceSelector: name('eve-acme-shop-prod') },
      { namespaceSelector: name('eve-acme-shop-staging') },
      { namespaceSelector: name('eve-acme-portal-prod') },
      { namespaceSelector: name('eve-runners'), podSelector: { matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': 'proj_shop' } } },
      { namespaceSelector: name('eve-runners'), podSelector: { matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': 'proj_portal' } } },
      { namespaceSelector: name('eve'), podSelector: { matchLabels: { 'eve.horizon/runner': 'true', 'eve.horizon/project-id': 'proj_shop' } } },
    ]));
    expect(from).toHaveLength(9);
    // Nothing that admits a whole other namespace beyond those named.
    expect(from.some((peer: any) => peer.ipBlock || (peer.namespaceSelector && Object.keys(peer.namespaceSelector).length === 0))).toBe(false);
  });

  it('admits from the platform namespace only named platform workloads and the project runners, never any other pod there', () => {
    // Tenant code runs in the platform namespace too: agent runtime inline
    // jobs, the shared buildkitd, kaniko Jobs and legacy pipeline steps in
    // the worker. None of them may reach an app pod.
    expect(api.PLATFORM_INGRESS_WORKLOADS).toEqual(['eve-api']);
    const [policy] = api.envIngressPolicies(NS, 'strict', PEERS, SETTINGS);
    const fromPlatform = policy.spec.ingress[0].from.filter((peer: any) =>
      JSON.stringify(peer.namespaceSelector) === JSON.stringify(name('eve')));
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

  it('under audit writes an allow-all companion first, so nothing is refused', () => {
    const policies = api.envIngressPolicies(NS, 'audit', PEERS, SETTINGS);
    expect(policies.map((p: any) => p.metadata.name)).toEqual(['eve-ingress-audit', 'eve-ingress']);
    expect(policies[0].spec).toEqual({ podSelector: {}, policyTypes: ['Ingress'], ingress: [{}] });
  });

  it('under legacy writes nothing', () => {
    expect(api.envIngressPolicies(NS, 'legacy', PEERS, SETTINGS)).toEqual([]);
  });

  it('lists each namespace and runner project once', () => {
    const [policy] = api.envIngressPolicies(NS, 'strict', {
      projectNamespaces: [NS, NS], consumerNamespaces: [NS], runnerProjects: ['proj_shop', 'proj_shop'],
    }, SETTINGS);
    const keys = policy.spec.ingress[0].from.map((peer: any) => JSON.stringify(peer));
    expect(new Set(keys).size).toBe(keys.length);
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
