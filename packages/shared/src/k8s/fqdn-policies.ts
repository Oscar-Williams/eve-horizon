/**
 * egress.allow_hosts in the cluster: GKE `FQDNNetworkPolicy` objects
 * (`networking.gke.io/v1alpha1`, egress only), written by the worker when
 * `EVE_EGRESS_FQDN_PROVIDER=gke`.
 *
 * - One policy per host and port. GKE resolves each policy to at most 50
 *   IPv4 and IPv6 addresses, and a large CDN name alone can come near that,
 *   so hosts never share a policy.
 * - Runner policies live in the runner namespaces and select a project's
 *   runner pods (`eve.horizon/runner`, `eve.horizon/project-id`): the
 *   project's list, the default hosts of the harnesses and the git host.
 * - Env policies select every pod of the namespace for the project's list,
 *   and a service's pods (`eve.component`) for that service's list.
 *
 * FQDN policies add up with NetworkPolicies, so beside the internet rule of
 * `egress.default_deny` they change nothing: under `audit` they are written
 * for review, and only under `strict`, where the internet rule is left out,
 * do they decide what a pod reaches. GKE filters by the addresses a name
 * resolves to, so other hosts on the same addresses (Google APIs, CDNs) are
 * reachable too, and DNS lookups succeed for any name.
 */
import { createHash } from 'node:crypto';
import { harnessEgressHosts } from '../harnesses/egress-hosts.js';
import { RUNNER_LABELS } from '../invoke/runner-sandbox.js';
import { canonicalEgressHosts, egressHostKey, gitEgressHost, type EgressHost } from './egress-hosts.js';
import { toK8sLabelValue } from './names.js';
import type { LabelSelector } from './egress-policies.js';

/** The project rule these policies carry out. */
export const ALLOW_HOSTS_RULE = 'egress.allow_hosts';

export const FQDN_POLICY_API_VERSION = 'networking.gke.io/v1alpha1';
export const FQDN_POLICY_KIND = 'FQDNNetworkPolicy';
export const FQDN_POLICY_GROUP = 'networking.gke.io';
export const FQDN_POLICY_VERSION = 'v1alpha1';
export const FQDN_POLICY_PLURAL = 'fqdnnetworkpolicies';

/** `eve.horizon/egress=fqdn` on every FQDN policy Eve writes, so a sync deletes only Eve's. */
export const FQDN_POLICY_LABEL = 'eve.horizon/egress';
export const FQDN_POLICY_LABEL_VALUE = 'fqdn';
export const FQDN_HOST_ANNOTATION = 'eve.horizon/egress-host';

/** Who enforces host allow lists: GKE's FQDNNetworkPolicy, or nothing. */
export const EGRESS_FQDN_PROVIDERS = ['none', 'gke'] as const;
export type EgressFqdnProvider = (typeof EGRESS_FQDN_PROVIDERS)[number];

export const EGRESS_PROVIDER_MISSING_MESSAGE = 'egress allow lists need a provider (EVE_EGRESS_FQDN_PROVIDER)';

/**
 * `strict` egress.allow_hosts with no provider: nothing could allow the
 * declared hosts, so the deploy or the job is refused rather than run with
 * no internet at all.
 */
export class EgressProviderMissingError extends Error {
  constructor() {
    super(`${EGRESS_PROVIDER_MISSING_MESSAGE} (rule ${ALLOW_HOSTS_RULE})`);
    this.name = 'EgressProviderMissingError';
  }
}

/** `EVE_EGRESS_FQDN_PROVIDER`; anything other than `gke` is `none`. */
export function egressFqdnProvider(value: string | null | undefined = process.env.EVE_EGRESS_FQDN_PROVIDER): EgressFqdnProvider {
  return value?.trim().toLowerCase() === 'gke' ? 'gke' : 'none';
}

export interface FqdnNetworkPolicy {
  apiVersion: typeof FQDN_POLICY_API_VERSION;
  kind: typeof FQDN_POLICY_KIND;
  metadata: {
    name: string;
    namespace: string;
    labels: Record<string, string>;
    annotations: Record<string, string>;
  };
  spec: {
    podSelector: LabelSelector;
    egress: Array<{
      matches: Array<{ name: string } | { pattern: string }>;
      ports: Array<{ protocol: 'TCP'; port: number }>;
    }>;
  };
}

/** `eve-fqdn-<16 hex>` of the scope and the host: stable for the same pair, distinct across projects and services. */
export function fqdnPolicyName(scope: string, host: EgressHost): string {
  return `eve-fqdn-${createHash('sha256').update(`${scope}\n${egressHostKey(host)}`).digest('hex').slice(0, 16)}`;
}

function fqdnPolicy(
  namespace: string,
  scope: string,
  projectId: string,
  podSelector: LabelSelector,
  host: EgressHost,
): FqdnNetworkPolicy {
  return {
    apiVersion: FQDN_POLICY_API_VERSION,
    kind: FQDN_POLICY_KIND,
    metadata: {
      name: fqdnPolicyName(scope, host),
      namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'eve-horizon',
        [FQDN_POLICY_LABEL]: FQDN_POLICY_LABEL_VALUE,
        [RUNNER_LABELS.projectId]: projectId,
      },
      annotations: { [FQDN_HOST_ANNOTATION]: egressHostKey(host) },
    },
    spec: {
      podSelector,
      egress: [{
        matches: [host.name !== undefined ? { name: host.name } : { pattern: host.pattern! }],
        ports: [{ protocol: 'TCP', port: host.port }],
      }],
    },
  };
}

/**
 * What a project's runner pods may reach: its declared list, the default
 * hosts of the given harnesses (all of them when none are named: a job may
 * pick any harness) and the git host of its repository, each once.
 */
export function runnerAllowHosts(input: {
  projectHosts: readonly unknown[];
  harnesses?: readonly string[];
  repoUrl?: string | null;
}): EgressHost[] {
  const git = gitEgressHost(input.repoUrl);
  return canonicalEgressHosts([
    ...canonicalEgressHosts(input.projectHosts),
    ...harnessEgressHosts(input.harnesses),
    ...(git ? [git] : []),
  ]);
}

/** One policy per host for a project's runner pods in a runner namespace. */
export function runnerFqdnPolicies(namespace: string, projectId: string, hosts: readonly EgressHost[]): FqdnNetworkPolicy[] {
  const selector = { matchLabels: { [RUNNER_LABELS.runner]: 'true', [RUNNER_LABELS.projectId]: projectId } };
  return canonicalEgressHosts(hosts).map((host) => fqdnPolicy(namespace, `runner\n${projectId}`, projectId, selector, host));
}

/** One policy per host in an env namespace: the project list for every pod, a service's list for its pods. */
export function envFqdnPolicies(
  namespace: string,
  projectId: string,
  lists: { project: readonly EgressHost[]; services: Readonly<Record<string, readonly EgressHost[]>> },
): FqdnNetworkPolicy[] {
  const policies = canonicalEgressHosts(lists.project)
    .map((host) => fqdnPolicy(namespace, 'env', projectId, {}, host));
  for (const [service, hosts] of Object.entries(lists.services)) {
    const component = toK8sLabelValue(service, 'component');
    const selector = { matchLabels: { 'eve.component': component } };
    policies.push(...canonicalEgressHosts(hosts)
      .map((host) => fqdnPolicy(namespace, `service\n${component}`, projectId, selector, host)));
  }
  return policies;
}
