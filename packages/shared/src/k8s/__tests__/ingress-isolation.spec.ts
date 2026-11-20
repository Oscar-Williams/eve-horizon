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

describe('podSecurityAdmissionLabels', () => {
  it('under strict enforces the namespace level, beside warn and audit', () => {
    expect(api.podSecurityAdmissionLabels('strict', 'restricted')).toEqual({
      'pod-security.kubernetes.io/enforce': 'restricted',
      'pod-security.kubernetes.io/enforce-version': 'latest',
      'pod-security.kubernetes.io/warn': 'restricted',
      'pod-security.kubernetes.io/audit': 'restricted',
    });
    expect(api.podSecurityAdmissionLabels('strict', 'baseline')['pod-security.kubernetes.io/enforce']).toBe('baseline');
  });

  it('under audit sets warn and audit only, and takes enforce away', () => {
    expect(api.podSecurityAdmissionLabels('audit', 'restricted')).toEqual({
      'pod-security.kubernetes.io/enforce': null,
      'pod-security.kubernetes.io/enforce-version': null,
      'pod-security.kubernetes.io/warn': 'restricted',
      'pod-security.kubernetes.io/audit': 'restricted',
    });
  });

  it('under legacy sets nothing, and takes away an enforce a strict profile left', () => {
    expect(api.podSecurityAdmissionLabels('legacy', 'restricted')).toEqual({
      'pod-security.kubernetes.io/enforce': null,
      'pod-security.kubernetes.io/enforce-version': null,
    });
  });
});
