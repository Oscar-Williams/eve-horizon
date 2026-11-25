import { describe, expect, it } from 'vitest';
import {
  ENV_EGRESS_AUDIT_POLICY,
  ENV_EGRESS_METADATA_POLICY,
  ENV_EGRESS_POLICY,
  EVE_API_PUBLIC_PORT,
  RUNNER_DENY_POLICY,
  RUNNER_INGRESS_POLICY,
  RUNNER_LABEL,
  RUNNER_PROJECT_LABEL,
  WORKLOAD_IDENTITY_LABEL,
  envEgressPolicies,
  parseCidrList,
  parsePolicyEnforced,
  runnerDenyPolicies,
  runnerEgressPolicies,
  runnerIngressPolicies,
  runnerPolicyName,
  type EgressNetworkPolicy,
} from '../egress-policies.js';

/**
 * egress.default_deny: the NetworkPolicies Eve writes. Env namespaces get
 * `eve-egress` (and `eve-egress-metadata` for Workload Identity pods), with
 * an allow-all `eve-egress-audit` beside them under `audit`; runner pods are
 * denied by a static `eve-runner-deny` and allowed per project, and take
 * connections only from the worker (`eve-runner-ingress`).
 */
const settings = { platformNamespace: 'eve', privateCidrs: ['10.20.0.0/16'] };
const NS = 'eve-acme-shop-prod';
const PROJECT = 'proj_01jabcdefghjkmnpqrstvwxyz0';

type Rule = EgressNetworkPolicy['spec']['egress'][number];
type Peer = NonNullable<Rule['to']>[number];

/**
 * Cluster DNS on 53: kube-dns, and node-local-dns, which NodeLocal DNSCache
 * runs as ordinary pods on GKE Dataplane V2 (queries to the kube-dns Service
 * address are answered there, so a rule naming kube-dns alone drops them).
 */
const DNS_RULE: Rule = {
  to: [{
    namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'kube-system' } },
    podSelector: { matchExpressions: [{ key: 'k8s-app', operator: 'In', values: ['kube-dns', 'node-local-dns'] }] },
  }],
  ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }],
};

function byName(policies: EgressNetworkPolicy[], name: string): EgressNetworkPolicy {
  const policy = policies.find((p) => p.metadata.name === name);
  if (!policy) throw new Error(`no policy ${name} in ${policies.map((p) => p.metadata.name).join(', ')}`);
  return policy;
}

function peers(policy: EgressNetworkPolicy): Array<{ peer: Peer; ports: Rule['ports'] }> {
  return policy.spec.egress.flatMap((rule) => (rule.to ?? []).map((peer) => ({ peer, ports: rule.ports })));
}

function strictSets(): EgressNetworkPolicy[] {
  return [
    ...envEgressPolicies(NS, 'strict', {}, settings),
    ...runnerEgressPolicies('eve-runners', PROJECT, 'strict', {}, settings),
    ...runnerEgressPolicies('eve', PROJECT, 'strict', {}, settings),
    ...runnerDenyPolicies({ runnerNamespace: 'eve-runners', platformNamespace: 'eve' }),
  ];
}

function containsMetadataServer(peer: Peer): boolean {
  if (!peer.ipBlock) return false;
  const [base, bits] = peer.ipBlock.cidr.split('/');
  if (peer.ipBlock.except?.some((cidr) => cidr === '169.254.0.0/16')) return false;
  if (bits === '0') return true;
  return base.startsWith('169.254.');
}

describe('env egress policies', () => {
  it('under audit applies the allow-all companion first, then the strict set', () => {
    const names = envEgressPolicies(NS, 'audit', {}, settings).map((p) => p.metadata.name);
    expect(names).toEqual([ENV_EGRESS_AUDIT_POLICY, ENV_EGRESS_POLICY, ENV_EGRESS_METADATA_POLICY]);
    const companion = byName(envEgressPolicies(NS, 'audit', {}, settings), ENV_EGRESS_AUDIT_POLICY);
    expect(companion.spec).toEqual({ podSelector: {}, policyTypes: ['Egress'], egress: [{}] });
  });

  it('under strict applies the strict set without the companion, and under legacy nothing', () => {
    expect(envEgressPolicies(NS, 'strict', {}, settings).map((p) => p.metadata.name))
      .toEqual([ENV_EGRESS_POLICY, ENV_EGRESS_METADATA_POLICY]);
    expect(envEgressPolicies(NS, 'legacy', {}, settings)).toEqual([]);
  });

  it('labels every policy as Eve-managed env egress, in the env namespace, Egress only', () => {
    for (const policy of envEgressPolicies(NS, 'audit', {}, settings)) {
      expect(policy.apiVersion).toBe('networking.k8s.io/v1');
      expect(policy.kind).toBe('NetworkPolicy');
      expect(policy.metadata.namespace).toBe(NS);
      expect(policy.metadata.labels).toMatchObject({
        'app.kubernetes.io/managed-by': 'eve-horizon',
        'eve.horizon/egress': 'env',
      });
      expect(policy.spec.policyTypes).toEqual(['Egress']);
    }
  });

  it('allows the metadata server only in eve-egress-metadata, for pods with Workload Identity', () => {
    for (const policy of strictSets()) {
      if (policy.metadata.name === ENV_EGRESS_METADATA_POLICY) continue;
      for (const { peer } of peers(policy)) {
        expect(containsMetadataServer(peer), `${policy.metadata.name}: ${JSON.stringify(peer)}`).toBe(false);
      }
    }
    const metadata = byName(envEgressPolicies(NS, 'strict', {}, settings), ENV_EGRESS_METADATA_POLICY);
    expect(metadata.spec.podSelector).toEqual({ matchLabels: { [WORKLOAD_IDENTITY_LABEL]: 'true' } });
    expect(metadata.spec.egress).toEqual([
      { to: [{ ipBlock: { cidr: '169.254.169.254/32' } }], ports: [{ protocol: 'TCP', port: 80 }] },
      { to: [{ ipBlock: { cidr: '169.254.169.252/32' } }], ports: [{ protocol: 'TCP', port: 988 }] },
    ]);
  });

  it('allows no platform pod but eve-api, and that only on the public port', () => {
    for (const policy of strictSets()) {
      for (const { peer, ports } of peers(policy)) {
        const ns = peer.namespaceSelector?.matchLabels?.['kubernetes.io/metadata.name'];
        if (ns !== 'eve') continue;
        expect(peer.podSelector, `${policy.metadata.name}`).toEqual({ matchLabels: { 'app.kubernetes.io/name': 'eve-api' } });
        expect(ports).toEqual([{ protocol: 'TCP', port: EVE_API_PUBLIC_PORT }]);
      }
    }
    expect(EVE_API_PUBLIC_PORT).toBe(4701);
  });

  it('opens the internet except private ranges, CGNAT, link-local and network.private_cidrs', () => {
    const policy = byName(envEgressPolicies(NS, 'strict', {}, settings), ENV_EGRESS_POLICY);
    const internet = peers(policy).filter(({ peer }) => peer.ipBlock?.cidr === '0.0.0.0/0');
    expect(internet).toHaveLength(1);
    expect(internet[0].ports).toBeUndefined();
    expect(internet[0].peer.ipBlock!.except).toEqual([
      '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16', '100.64.0.0/10', '169.254.0.0/16', '10.20.0.0/16',
    ]);
  });

  it('reaches the ingress controller pods on their container ports, for calls to public hosts', () => {
    const policy = byName(envEgressPolicies(NS, 'strict', {}, settings), ENV_EGRESS_POLICY);
    const traefik = peers(policy).filter(({ peer }) => peer.podSelector?.matchLabels?.['app.kubernetes.io/name'] === 'traefik');
    expect(traefik).toEqual([{
      peer: {
        namespaceSelector: { matchExpressions: [{ key: 'kubernetes.io/metadata.name', operator: 'In', values: ['traefik', 'kube-system'] }] },
        podSelector: { matchLabels: { 'app.kubernetes.io/name': 'traefik' } },
      },
      ports: [{ protocol: 'TCP', port: 8000 }, { protocol: 'TCP', port: 8443 }],
    }]);
  });

  it('allows DNS to kube-dns or node-local-dns, and the namespace itself', () => {
    const policy = byName(envEgressPolicies(NS, 'strict', {}, settings), ENV_EGRESS_POLICY);
    expect(policy.spec.podSelector).toEqual({});
    expect(policy.spec.egress).toContainEqual(DNS_RULE);
    expect(policy.spec.egress).toContainEqual({ to: [{ podSelector: {} }] });
  });

  it('gives env pods, project runner pods and the static runner deny the same DNS rule, and DNS nowhere else', () => {
    for (const policy of strictSets()) {
      const dns = policy.spec.egress.filter((rule) => rule.ports?.some((port) => port.port === 53));
      if (policy.metadata.name === ENV_EGRESS_METADATA_POLICY) {
        expect(dns).toEqual([]);
        continue;
      }
      expect(dns).toEqual([DNS_RULE]);
    }
  });

  it('adds a managed database as a /32 on its port, and app-link producers on theirs', () => {
    const policy = byName(envEgressPolicies(NS, 'strict', {
      cidrs: [{ cidr: '10.40.0.3/32', port: 5432 }],
      namespaces: [{ namespace: 'eve-acme-api-prod', ports: [3000] }, { namespace: 'eve-acme-shop-staging' }],
    }, settings), ENV_EGRESS_POLICY);
    expect(policy.spec.egress).toContainEqual({ to: [{ ipBlock: { cidr: '10.40.0.3/32' } }], ports: [{ protocol: 'TCP', port: 5432 }] });
    expect(policy.spec.egress).toContainEqual({
      to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve-acme-api-prod' } } }],
      ports: [{ protocol: 'TCP', port: 3000 }],
    });
    expect(policy.spec.egress).toContainEqual({
      to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve-acme-shop-staging' } } }],
    });
  });
});

describe('runner egress policies', () => {
  it('names the project policy validly for an id with _, and keeps the real id in the selector', () => {
    const name = runnerPolicyName(PROJECT);
    expect(name).toMatch(/^eve-runner-proj-01jabcdefghjkmnpqrstvwxyz0-[0-9a-f]{8}$/);
    expect(name.length).toBeLessThanOrEqual(57);
    expect(runnerPolicyName('proj_a')).not.toBe(runnerPolicyName('proj-a'));
    const long = runnerPolicyName(`proj_${'x'.repeat(80)}`);
    expect(`${long}-audit`.length).toBeLessThanOrEqual(63);
    expect(long).toMatch(/^[a-z0-9]([-a-z0-9]*[a-z0-9])?$/);

    const [policy] = runnerEgressPolicies('eve-runners', PROJECT, 'strict', {}, settings);
    expect(policy.metadata).toMatchObject({
      name,
      namespace: 'eve-runners',
      labels: { 'eve.horizon/egress': 'runner', [RUNNER_PROJECT_LABEL]: PROJECT },
    });
    expect(policy.spec.podSelector).toEqual({ matchLabels: { [RUNNER_LABEL]: 'true', [RUNNER_PROJECT_LABEL]: PROJECT } });
  });

  it('selects the same runner pods in the platform namespace (org filesystem jobs)', () => {
    const [policy] = runnerEgressPolicies('eve', PROJECT, 'strict', {}, settings);
    expect(policy.metadata.namespace).toBe('eve');
    expect(policy.spec.podSelector).toEqual({ matchLabels: { [RUNNER_LABEL]: 'true', [RUNNER_PROJECT_LABEL]: PROJECT } });
  });

  it('gives strict the project policy, audit the companion first, and legacy the companion alone', () => {
    const name = runnerPolicyName(PROJECT);
    const names = (profile: 'legacy' | 'audit' | 'strict') =>
      runnerEgressPolicies('eve-runners', PROJECT, profile, {}, settings).map((p) => p.metadata.name);
    expect(names('strict')).toEqual([name]);
    expect(names('audit')).toEqual([`${name}-audit`, name]);
    expect(names('legacy')).toEqual([`${name}-audit`]);
    const companion = runnerEgressPolicies('eve-runners', PROJECT, 'legacy', {}, settings)[0];
    expect(companion.spec).toEqual({
      podSelector: { matchLabels: { [RUNNER_LABEL]: 'true', [RUNNER_PROJECT_LABEL]: PROJECT } },
      policyTypes: ['Egress'],
      egress: [{}],
    });
  });

  it('adds the project env namespaces and app-link producers, and never the runner namespace itself', () => {
    const [policy] = runnerEgressPolicies('eve-runners', PROJECT, 'strict', {
      namespaces: [{ namespace: 'eve-acme-shop-prod' }, { namespace: 'eve-acme-api-prod', ports: [3000] }],
    }, settings);
    expect(policy.spec.egress).toContainEqual({
      to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve-acme-shop-prod' } } }],
    });
    expect(policy.spec.egress).toContainEqual({
      to: [{ namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve-acme-api-prod' } } }],
      ports: [{ protocol: 'TCP', port: 3000 }],
    });
    expect(policy.spec.egress).not.toContainEqual({ to: [{ podSelector: {} }] });
  });
});

describe('runner deny', () => {
  const [runners, platform] = runnerDenyPolicies({ runnerNamespace: 'eve-runners', platformNamespace: 'eve' });

  it('selects every runner pod, warm or claimed, and allows only DNS and eve-api on the public port', () => {
    expect(RUNNER_LABEL).toBe('eve.horizon/runner');
    expect(runners.metadata).toMatchObject({ name: RUNNER_DENY_POLICY, namespace: 'eve-runners' });
    expect(runners.spec.podSelector).toEqual({ matchLabels: { [RUNNER_LABEL]: 'true' } });
    expect(runners.spec.policyTypes).toEqual(['Egress']);
    expect(runners.spec.egress).toEqual([
      DNS_RULE,
      {
        to: [{
          namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve' } },
          podSelector: { matchLabels: { 'app.kubernetes.io/name': 'eve-api' } },
        }],
        ports: [{ protocol: 'TCP', port: 4701 }],
      },
    ]);
  });

  it('selects the plain runner pods in the platform namespace the same way', () => {
    expect(platform.metadata).toMatchObject({ name: RUNNER_DENY_POLICY, namespace: 'eve' });
    expect(platform.spec.podSelector).toEqual(runners.spec.podSelector);
    expect(platform.spec.egress).toEqual(runners.spec.egress);
  });
});

describe('runner ingress', () => {
  const [runners, platform] = runnerIngressPolicies({ runnerNamespace: 'eve-runners', platformNamespace: 'eve' });

  it('lets only the worker reach runner pods, only on the submit port 4749', () => {
    for (const [policy, ns] of [[runners, 'eve-runners'], [platform, 'eve']] as const) {
      expect(policy.metadata).toMatchObject({ name: RUNNER_INGRESS_POLICY, namespace: ns });
      expect(policy.spec).toEqual({
        podSelector: { matchLabels: { [RUNNER_LABEL]: 'true' } },
        policyTypes: ['Ingress'],
        ingress: [{
          from: [{
            namespaceSelector: { matchLabels: { 'kubernetes.io/metadata.name': 'eve' } },
            podSelector: { matchLabels: { 'app.kubernetes.io/name': 'eve-worker' } },
          }],
          ports: [{ protocol: 'TCP', port: 4749 }],
        }],
      });
    }
  });
});

describe('network settings', () => {
  it('reads network.private_cidrs as IPv4 CIDRs, canonical, and names what it cannot use', () => {
    expect(parseCidrList('10.20.1.5/16, 192.0.2.7/32 203.0.113.0/24')).toEqual({
      cidrs: ['10.20.0.0/16', '192.0.2.7/32', '203.0.113.0/24'], invalid: [],
    });
    expect(parseCidrList('["198.51.100.0/24"]')).toEqual({ cidrs: ['198.51.100.0/24'], invalid: [] });
    expect(parseCidrList('nope, ::1/128, 0.0.0.0/0, 10.0.0.0/33, 300.1.1.1/8')).toEqual({
      cidrs: [], invalid: ['nope', '::1/128', '0.0.0.0/0', '10.0.0.0/33', '300.1.1.1/8'],
    });
    expect(parseCidrList(null)).toEqual({ cidrs: [], invalid: [] });
  });

  it('reads network.policy_enforced as true, false or unknown', () => {
    expect(parsePolicyEnforced('true')).toBe(true);
    expect(parsePolicyEnforced('false')).toBe(false);
    expect(parsePolicyEnforced(null)).toBeNull();
    expect(parsePolicyEnforced('maybe')).toBeNull();
  });
});
