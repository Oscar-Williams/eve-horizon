/**
 * network.ingress_isolation (rule set 3): who may connect to an env
 * namespace's pods.
 *
 * `eve-ingress` selects every pod and admits, on any port:
 * - the ingress controller (Traefik), for the env's public and private hosts;
 * - the platform workloads that call app pods, by their stable
 *   `app.kubernetes.io/name` label (PLATFORM_INGRESS_WORKLOADS): only the
 *   API, which fetches API specs, delivers webhooks to private targets and
 *   queries env databases. Never any other pod there: tenant code runs in
 *   the platform namespace too (agent runtime inline jobs, buildkitd, kaniko
 *   Jobs, legacy pipeline steps in the worker);
 * - the project's own env namespaces, and its runner pods;
 * - the env namespaces and runner pods of projects that consume its app
 *   links (live API grants for this env).
 *
 * Under `audit` the allow-all `eve-ingress-audit` sits beside it, so nothing
 * is refused; under `legacy` there is neither. These carry
 * `eve.horizon/ingress=env`, never `eve.horizon/egress`, so the egress sync
 * never deletes them, nor this sync the egress policies.
 */
import { RUNNER_LABELS } from '../invoke/runner-sandbox.js';
import type { SecurityProfile } from '../security/profile.js';
import {
  DEFAULT_PLATFORM_NAMESPACE,
  INGRESS_CONTROLLER_NAMESPACES,
  INGRESS_CONTROLLER_POD_LABELS,
  type LabelSelector,
  type NetworkPolicyPeer,
} from './egress-policies.js';

/** The project rule these policies carry out. */
export const INGRESS_RULE = 'network.ingress_isolation';

/**
 * The platform workloads (`app.kubernetes.io/name` in the platform
 * namespace) that connect to app pods: the API (spec fetches, webhooks with
 * private targets allowed, `eve db` queries). The worker, orchestrator and
 * gateway reach apps only through the Kubernetes API; the agent runtime,
 * buildkitd and kaniko run tenant code and are never admitted.
 */
export const PLATFORM_INGRESS_WORKLOADS: readonly string[] = ['eve-api'];

export const ENV_INGRESS_POLICY = 'eve-ingress';
export const ENV_INGRESS_AUDIT_POLICY = 'eve-ingress-audit';

/** Label on every ingress policy Eve writes (value `env`). */
export const INGRESS_POLICY_LABEL = 'eve.horizon/ingress';

/** Who may call an env namespace, besides the ingress controller and the platform. */
export interface IngressPeers {
  /** The project's own env namespaces (this one included). */
  projectNamespaces: readonly string[];
  /** Env namespaces of projects consuming this env's app links. */
  consumerNamespaces: readonly string[];
  /** Projects whose runner pods may connect: the project and its consumers. */
  runnerProjects: readonly string[];
}

export interface IngressSettings {
  /** Where the platform runs (default `eve`); plain-pod runners run there too. */
  platformNamespace?: string;
  /** Where runner pods run (default `eve-runners`). */
  runnerNamespace?: string;
}

export interface EnvIngressNetworkPolicy {
  apiVersion: 'networking.k8s.io/v1';
  kind: 'NetworkPolicy';
  metadata: { name: string; namespace: string; labels: Record<string, string> };
  spec: {
    podSelector: LabelSelector;
    policyTypes: ['Ingress'];
    ingress: Array<{ from?: NetworkPolicyPeer[] }>;
  };
}

const NAMESPACE_NAME = 'kubernetes.io/metadata.name';
const WORKLOAD_NAME_LABEL = 'app.kubernetes.io/name';
const byName = (namespace: string): LabelSelector => ({ matchLabels: { [NAMESPACE_NAME]: namespace } });

function policy(name: string, namespace: string, ingress: Array<{ from?: NetworkPolicyPeer[] }>): EnvIngressNetworkPolicy {
  return {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: { name, namespace, labels: { 'app.kubernetes.io/managed-by': 'eve-horizon', [INGRESS_POLICY_LABEL]: 'env' } },
    spec: { podSelector: {}, policyTypes: ['Ingress'], ingress },
  };
}

/** The sources `eve-ingress` admits, each once. */
function ingressPeers(peers: IngressPeers, settings: IngressSettings): NetworkPolicyPeer[] {
  const platform = settings.platformNamespace ?? DEFAULT_PLATFORM_NAMESPACE;
  const runnerNamespaces = [...new Set([settings.runnerNamespace ?? 'eve-runners', platform])];
  const list: NetworkPolicyPeer[] = [
    {
      namespaceSelector: { matchExpressions: [{ key: NAMESPACE_NAME, operator: 'In', values: [...INGRESS_CONTROLLER_NAMESPACES] }] },
      podSelector: { matchLabels: { ...INGRESS_CONTROLLER_POD_LABELS } },
    },
    {
      namespaceSelector: byName(platform),
      podSelector: { matchExpressions: [{ key: WORKLOAD_NAME_LABEL, operator: 'In', values: [...PLATFORM_INGRESS_WORKLOADS] }] },
    },
    ...[...peers.projectNamespaces, ...peers.consumerNamespaces].map((namespace) => ({ namespaceSelector: byName(namespace) })),
    ...runnerNamespaces.flatMap((namespace) => [...peers.runnerProjects].map((projectId) => ({
      namespaceSelector: byName(namespace),
      podSelector: { matchLabels: { [RUNNER_LABELS.runner]: 'true', [RUNNER_LABELS.projectId]: projectId } },
    }))),
  ];
  const seen = new Set<string>();
  return list.filter((peer) => {
    const key = JSON.stringify(peer);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * The ingress policies an env namespace should hold under a profile, in the
 * order to write them (the companion first, so moving to `audit` refuses
 * nothing). Any other Eve ingress policy there is to be deleted after.
 */
export function envIngressPolicies(
  namespace: string,
  profile: SecurityProfile,
  peers: IngressPeers,
  settings: IngressSettings = {},
): EnvIngressNetworkPolicy[] {
  if (profile === 'legacy') return [];
  const strict = policy(ENV_INGRESS_POLICY, namespace, [{ from: ingressPeers(peers, settings) }]);
  return profile === 'strict' ? [strict] : [policy(ENV_INGRESS_AUDIT_POLICY, namespace, [{}]), strict];
}
