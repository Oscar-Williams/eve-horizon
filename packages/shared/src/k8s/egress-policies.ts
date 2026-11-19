/**
 * egress.default_deny: the NetworkPolicies that limit where tenant pods and
 * runner pods may connect.
 *
 * - **Env namespaces** get `eve-egress` (DNS, the namespace itself, the API
 *   on its public port, the ingress controller for calls to public hosts,
 *   the internet outside private ranges, and the env's extras) and
 *   `eve-egress-metadata` (the metadata server, for pods whose service
 *   account has Workload Identity). Under `audit` the allow-all
 *   `eve-egress-audit` sits beside them, so nothing is blocked; under
 *   `strict` it is removed; under `legacy` there is none of them.
 * - **Runner pods** fail closed: the static `eve-runner-deny` (in k8s/base,
 *   never written by Eve's controllers) selects every runner pod and allows
 *   only DNS and the API. Each project's `eve-runner-<project>` adds the
 *   rest by the project label, with an allow-all `-audit` companion under
 *   `audit` and, because the deny is always there, under `legacy` alone.
 *   The static `eve-runner-ingress` lets only the worker reach runner pods.
 *
 * NetworkPolicy matches the destination pod's port after Service
 * translation, so in-cluster ports here are container ports.
 */
import { createHash } from 'node:crypto';
import type { SecurityProfile } from '../security/profile.js';

/** The project rule these policies carry out. */
export const EGRESS_RULE = 'egress.default_deny';

export const ENV_EGRESS_POLICY = 'eve-egress';
export const ENV_EGRESS_AUDIT_POLICY = 'eve-egress-audit';
export const ENV_EGRESS_METADATA_POLICY = 'eve-egress-metadata';
export const RUNNER_DENY_POLICY = 'eve-runner-deny';
export const RUNNER_INGRESS_POLICY = 'eve-runner-ingress';

/** Label on every policy Eve writes: `env` or `runner`. */
export const EGRESS_POLICY_LABEL = 'eve.horizon/egress';
/** Every runner pod, warm or claimed, sandbox or plain. */
export const RUNNER_LABEL = 'eve.horizon/runner';
/** The project a claimed runner pod works for (also on its runner policies). */
export const RUNNER_PROJECT_LABEL = 'eve.horizon/project-id';
/** Set by the deployer on pods whose service account has Workload Identity. */
export const WORKLOAD_IDENTITY_LABEL = 'eve.workload_identity';

export const DEFAULT_PLATFORM_NAMESPACE = 'eve';
export const DEFAULT_RUNNER_NAMESPACE = 'eve-runners';

/** The API's public container port; its internal port (`/internal/*`) is never allowed. */
export const EVE_API_PUBLIC_PORT = 4701;
/** What apps and runners get as `EVE_API_URL` when `EVE_API_APP_URL` is not set. */
export const DEFAULT_EVE_API_APP_URL = `http://eve-api.${DEFAULT_PLATFORM_NAMESPACE}.svc.cluster.local:${EVE_API_PUBLIC_PORT}`;
/** The port runner pods take the worker's submit on. */
export const RUNNER_SUBMIT_PORT = 4749;

/** Never reached through the internet rule: private ranges, CGNAT and link-local (the metadata server). */
export const INTERNET_EXCLUDED_CIDRS: readonly string[] = [
  '10.0.0.0/8',
  '172.16.0.0/12',
  '192.168.0.0/16',
  '100.64.0.0/10',
  '169.254.0.0/16',
];

/**
 * The ingress controller (Traefik), for calls to the instance's own public
 * hosts, which hairpin to its pods. `traefik` on managed installs,
 * `kube-system` on k3s.
 */
export const INGRESS_CONTROLLER_NAMESPACES: readonly string[] = ['traefik', 'kube-system'];
export const INGRESS_CONTROLLER_POD_LABELS: Readonly<Record<string, string>> = { 'app.kubernetes.io/name': 'traefik' };
export const INGRESS_CONTROLLER_PORTS: readonly number[] = [8000, 8443];

/** The GKE metadata server (and its Workload Identity endpoint). */
export const METADATA_SERVER_ENDPOINTS: ReadonlyArray<{ cidr: string; port: number }> = [
  { cidr: '169.254.169.254/32', port: 80 },
  { cidr: '169.254.169.252/32', port: 988 },
];

/** Instance setting: `true` where the CNI enforces NetworkPolicy (the infra template's output). */
export const NETWORK_POLICY_ENFORCED_SETTING = 'network.policy_enforced';
/** Instance setting: more IPv4 CIDRs the internet rule must not reach (VPC peerings, the node range). */
export const NETWORK_PRIVATE_CIDRS_SETTING = 'network.private_cidrs';

export interface LabelSelector {
  matchLabels?: Record<string, string>;
  matchExpressions?: Array<{ key: string; operator: 'In' | 'NotIn' | 'Exists' | 'DoesNotExist'; values?: string[] }>;
}

export interface NetworkPolicyPeer {
  namespaceSelector?: LabelSelector;
  podSelector?: LabelSelector;
  ipBlock?: { cidr: string; except?: string[] };
}

export interface NetworkPolicyPort {
  protocol: 'TCP' | 'UDP';
  port: number;
}

export interface EgressRule {
  to?: NetworkPolicyPeer[];
  ports?: NetworkPolicyPort[];
}

interface PolicyMetadata {
  name: string;
  namespace: string;
  labels: Record<string, string>;
}

export interface EgressNetworkPolicy {
  apiVersion: 'networking.k8s.io/v1';
  kind: 'NetworkPolicy';
  metadata: PolicyMetadata;
  spec: { podSelector: LabelSelector; policyTypes: ['Egress']; egress: EgressRule[] };
}

export interface IngressNetworkPolicy {
  apiVersion: 'networking.k8s.io/v1';
  kind: 'NetworkPolicy';
  metadata: PolicyMetadata;
  spec: {
    podSelector: LabelSelector;
    policyTypes: ['Ingress'];
    ingress: Array<{ from: NetworkPolicyPeer[]; ports: NetworkPolicyPort[] }>;
  };
}

/** What a namespace's pods need beyond the base set. */
export interface EgressExtras {
  /** In-cluster namespaces: app-link producers on their ports, a project's own envs on any port. */
  namespaces?: Array<{ namespace: string; ports?: number[] }>;
  /** Addresses outside the pod network on a port: a managed database's private IP as a /32. */
  cidrs?: Array<{ cidr: string; port: number }>;
}

export interface EgressSettings {
  /** Where `eve-api` runs (default `eve`). */
  platformNamespace?: string;
  /** `network.private_cidrs`, parsed. */
  privateCidrs?: readonly string[];
}

// ---------------------------------------------------------------------------
// Rules
// ---------------------------------------------------------------------------

const NAMESPACE_NAME = 'kubernetes.io/metadata.name';
const tcp = (port: number): NetworkPolicyPort => ({ protocol: 'TCP', port });
const namespaceSelector = (namespace: string): LabelSelector => ({ matchLabels: { [NAMESPACE_NAME]: namespace } });

function dnsRule(): EgressRule {
  return {
    to: [{ namespaceSelector: namespaceSelector('kube-system'), podSelector: { matchLabels: { 'k8s-app': 'kube-dns' } } }],
    ports: [{ protocol: 'UDP', port: 53 }, { protocol: 'TCP', port: 53 }],
  };
}

function apiRule(platformNamespace: string): EgressRule {
  return {
    to: [{
      namespaceSelector: namespaceSelector(platformNamespace),
      podSelector: { matchLabels: { 'app.kubernetes.io/name': 'eve-api' } },
    }],
    ports: [tcp(EVE_API_PUBLIC_PORT)],
  };
}

function ingressControllerRule(): EgressRule {
  return {
    to: [{
      namespaceSelector: { matchExpressions: [{ key: NAMESPACE_NAME, operator: 'In', values: [...INGRESS_CONTROLLER_NAMESPACES] }] },
      podSelector: { matchLabels: { ...INGRESS_CONTROLLER_POD_LABELS } },
    }],
    ports: INGRESS_CONTROLLER_PORTS.map(tcp),
  };
}

function internetRule(privateCidrs: readonly string[]): EgressRule {
  const except = [...new Set([...INTERNET_EXCLUDED_CIDRS, ...privateCidrs])];
  return { to: [{ ipBlock: { cidr: '0.0.0.0/0', except } }] };
}

function extraRules(extras: EgressExtras): EgressRule[] {
  const rules: EgressRule[] = [];
  for (const { cidr, port } of extras.cidrs ?? []) {
    rules.push({ to: [{ ipBlock: { cidr } }], ports: [tcp(port)] });
  }
  for (const { namespace, ports } of extras.namespaces ?? []) {
    rules.push({
      to: [{ namespaceSelector: namespaceSelector(namespace) }],
      ...(ports && ports.length > 0 ? { ports: ports.map(tcp) } : {}),
    });
  }
  return dedupeRules(rules);
}

function dedupeRules(rules: EgressRule[]): EgressRule[] {
  const seen = new Set<string>();
  return rules.filter((rule) => {
    const key = JSON.stringify(rule);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** DNS, the API on its public port, the ingress controller and the internet outside private ranges. */
function baseRules(settings: EgressSettings): EgressRule[] {
  return [
    dnsRule(),
    apiRule(settings.platformNamespace ?? DEFAULT_PLATFORM_NAMESPACE),
    ingressControllerRule(),
    internetRule(settings.privateCidrs ?? []),
  ];
}

function policy(
  name: string,
  namespace: string,
  labels: Record<string, string>,
  podSelector: LabelSelector,
  egress: EgressRule[],
): EgressNetworkPolicy {
  return {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: { name, namespace, labels: { 'app.kubernetes.io/managed-by': 'eve-horizon', ...labels } },
    spec: { podSelector, policyTypes: ['Egress'], egress },
  };
}

// ---------------------------------------------------------------------------
// Env namespaces
// ---------------------------------------------------------------------------

/**
 * The policies an env namespace should hold under a profile, in the order to
 * write them: the companion before the strict set, so moving from `legacy`
 * to `audit` never blocks anything. Any other Eve env policy in the namespace
 * is to be deleted after these are written.
 */
export function envEgressPolicies(
  namespace: string,
  profile: SecurityProfile,
  extras: EgressExtras,
  settings: EgressSettings = {},
): EgressNetworkPolicy[] {
  if (profile === 'legacy') return [];
  const labels = { [EGRESS_POLICY_LABEL]: 'env' };
  const [dns, ...rest] = baseRules(settings);
  const strict = policy(ENV_EGRESS_POLICY, namespace, labels, {}, [
    dns,
    { to: [{ podSelector: {} }] },
    ...rest,
    ...extraRules(extras),
  ]);
  const metadata = policy(
    ENV_EGRESS_METADATA_POLICY,
    namespace,
    labels,
    { matchLabels: { [WORKLOAD_IDENTITY_LABEL]: 'true' } },
    METADATA_SERVER_ENDPOINTS.map(({ cidr, port }) => ({ to: [{ ipBlock: { cidr } }], ports: [tcp(port)] })),
  );
  if (profile === 'strict') return [strict, metadata];
  return [policy(ENV_EGRESS_AUDIT_POLICY, namespace, labels, {}, [{}]), strict, metadata];
}

// ---------------------------------------------------------------------------
// Runner pods
// ---------------------------------------------------------------------------

const RUNNER_POLICY_PREFIX = 'eve-runner-';
const MAX_NAME = 63;
const AUDIT_SUFFIX = '-audit';

/**
 * `eve-runner-<project>-<8 hex>`: the id lowercased with anything outside
 * `[a-z0-9-]` as `-` (project ids hold `_`), and a hash of the real id so two
 * ids that read alike never share a name. Leaves room for `-audit`.
 */
export function runnerPolicyName(projectId: string): string {
  const hash = createHash('sha256').update(projectId).digest('hex').slice(0, 8);
  const room = MAX_NAME - RUNNER_POLICY_PREFIX.length - hash.length - 1 - AUDIT_SUFFIX.length;
  const slug = projectId.toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/-+/g, '-')
    .slice(0, room).replace(/^-+|-+$/g, '');
  return `${RUNNER_POLICY_PREFIX}${slug ? `${slug}-` : ''}${hash}`;
}

/**
 * The runner policies of one project in one runner namespace, in the order
 * to write them. `strict`: the project policy. `audit`: the allow-all
 * companion, then the project policy. `legacy`: the companion alone (the
 * static deny selects every runner pod, so a project with nothing would be
 * left with DNS and the API).
 */
export function runnerEgressPolicies(
  namespace: string,
  projectId: string,
  profile: SecurityProfile,
  extras: EgressExtras,
  settings: EgressSettings = {},
): EgressNetworkPolicy[] {
  const name = runnerPolicyName(projectId);
  const labels = { [EGRESS_POLICY_LABEL]: 'runner', [RUNNER_PROJECT_LABEL]: projectId };
  const selector = { matchLabels: { [RUNNER_LABEL]: 'true', [RUNNER_PROJECT_LABEL]: projectId } };
  const companion = policy(`${name}${AUDIT_SUFFIX}`, namespace, labels, selector, [{}]);
  if (profile === 'legacy') return [companion];
  const strict = policy(name, namespace, labels, selector, [...baseRules(settings), ...extraRules(extras)]);
  return profile === 'strict' ? [strict] : [companion, strict];
}

/**
 * The static `eve-runner-deny`, as k8s/base holds it: every runner pod in
 * the runner namespace and, for plain-pod runners (org filesystem jobs), in
 * the platform namespace, may reach only DNS and the API on its public port.
 * Pods from releases before runner labels carry no `eve.horizon/runner`, so
 * it never selects them.
 */
export function runnerDenyPolicies(namespaces: { runnerNamespace: string; platformNamespace: string }): EgressNetworkPolicy[] {
  return [namespaces.runnerNamespace, namespaces.platformNamespace].map((namespace) => policy(
    RUNNER_DENY_POLICY,
    namespace,
    {},
    { matchLabels: { [RUNNER_LABEL]: 'true' } },
    [dnsRule(), apiRule(namespaces.platformNamespace)],
  ));
}

/**
 * The static `eve-runner-ingress`: runner pods take connections only from
 * the worker, on the submit port. A warm pod accepts the first submit that
 * brings a key, so nothing else may reach it.
 */
export function runnerIngressPolicies(namespaces: { runnerNamespace: string; platformNamespace: string }): IngressNetworkPolicy[] {
  return [namespaces.runnerNamespace, namespaces.platformNamespace].map((namespace) => ({
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: { name: RUNNER_INGRESS_POLICY, namespace, labels: { 'app.kubernetes.io/managed-by': 'eve-horizon' } },
    spec: {
      podSelector: { matchLabels: { [RUNNER_LABEL]: 'true' } },
      policyTypes: ['Ingress'],
      ingress: [{
        from: [{
          namespaceSelector: namespaceSelector(namespaces.platformNamespace),
          podSelector: { matchLabels: { 'app.kubernetes.io/name': 'eve-worker' } },
        }],
        ports: [tcp(RUNNER_SUBMIT_PORT)],
      }],
    },
  }));
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

function parseIpv4(value: string): number | null {
  const parts = value.split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const octet = Number(part);
    if (octet > 255) return null;
    n = n * 256 + octet;
  }
  return n;
}

function formatIpv4(n: number): string {
  return [24, 16, 8, 0].map((shift) => Math.floor(n / 2 ** shift) % 256).join('.');
}

/** An IPv4 CIDR with its host bits cleared, or null. `/0` is refused: it would exclude the whole internet rule. */
export function canonicalIpv4Cidr(value: string): string | null {
  const match = /^([0-9.]+)\/(\d{1,2})$/.exec(value.trim());
  if (!match) return null;
  const address = parseIpv4(match[1]);
  const bits = Number(match[2]);
  if (address === null || bits < 1 || bits > 32) return null;
  const size = 2 ** (32 - bits);
  return `${formatIpv4(Math.floor(address / size) * size)}/${bits}`;
}

/** `network.private_cidrs`: comma or space separated, or a JSON array. */
export function parseCidrList(value: string | null | undefined): { cidrs: string[]; invalid: string[] } {
  if (!value || !value.trim()) return { cidrs: [], invalid: [] };
  let items: string[];
  try {
    const parsed = JSON.parse(value) as unknown;
    items = Array.isArray(parsed) ? parsed.map(String) : value.split(/[\s,]+/);
  } catch {
    items = value.split(/[\s,]+/);
  }
  const cidrs: string[] = [];
  const invalid: string[] = [];
  for (const item of items.map((i) => i.trim()).filter(Boolean)) {
    const cidr = canonicalIpv4Cidr(item);
    if (cidr) {
      if (!cidrs.includes(cidr)) cidrs.push(cidr);
    } else {
      invalid.push(item);
    }
  }
  return { cidrs, invalid };
}

/** `network.policy_enforced`: true, false, or null when unset or unreadable. */
export function parsePolicyEnforced(value: string | null | undefined): boolean | null {
  if (value === 'true') return true;
  if (value === 'false') return false;
  return null;
}
