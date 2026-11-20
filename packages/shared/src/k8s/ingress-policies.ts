/**
 * network.ingress_isolation (rule set 3): who may connect to an env
 * namespace's pods.
 *
 * Under `strict` Eve writes:
 * - `eve-ingress`, over every pod, any port: the platform workloads that
 *   call app pods, by their stable `app.kubernetes.io/name` label
 *   (PLATFORM_INGRESS_WORKLOADS): only the API, which fetches API specs,
 *   delivers webhooks to private targets and queries env databases. Never
 *   any other pod there: tenant code runs in the platform namespace too
 *   (agent runtime inline jobs, buildkitd, kaniko Jobs, legacy pipeline
 *   steps in the worker). And the project's own env namespaces and runner
 *   pods;
 * - `eve-ingress-svc-<service>`, over one service's pods (`eve.component`,
 *   the label the deployer sets on them): the ingress controller (Traefik)
 *   on the port the service's Ingress routes to, when it has one; and the
 *   env namespaces and runner pods of projects consuming it through app
 *   links (live API grants for this env), on the link's port.
 *
 * NetworkPolicies add up: each of these widens, for the pods it selects, a
 * project's own ingress policies. So under `audit` and `legacy` Eve writes
 * none (an allow-all companion would cancel every restriction a project
 * sets itself), and the caller records under `audit` what `strict` would
 * write. They carry `eve.horizon/ingress=env`, never `eve.horizon/egress`,
 * so the egress sync never deletes them, nor this sync the egress policies.
 */
import { RUNNER_LABELS } from '../invoke/runner-sandbox.js';
import { isPublicIngress, serviceIngressBlock } from '../security/public-ingress.js';
import type { SecurityProfile } from '../security/profile.js';
import {
  DEFAULT_PLATFORM_NAMESPACE,
  INGRESS_CONTROLLER_NAMESPACES,
  INGRESS_CONTROLLER_POD_LABELS,
  type LabelSelector,
  type NetworkPolicyPeer,
  type NetworkPolicyPort,
} from './egress-policies.js';
import { toK8sLabelValue, toK8sName } from './names.js';

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
/** Prefix of the per-service policies (`eve-ingress-svc-<service>`). */
export const ENV_INGRESS_SERVICE_POLICY_PREFIX = 'eve-ingress-svc-';

/** Label on every ingress policy Eve writes (value `env`). */
export const INGRESS_POLICY_LABEL = 'eve.horizon/ingress';

/** A service the ingress controller routes to, and the container port it calls. */
export interface IngressRoute {
  /** The service's name in the manifest. */
  service: string;
  port: number;
}

/** The app-link callers of one producer service. */
export interface AppLinkIngress {
  /** The service the API grant names. */
  service: string;
  /** Its port, as the consumers' egress has it; null when unknown (any port of its pods). */
  port: number | null;
  /** The consumers' env namespaces. */
  namespaces: readonly string[];
  /** The consumer projects whose runner pods may call it. */
  runnerProjects: readonly string[];
}

/** Who may call an env namespace, besides the platform's API. */
export interface IngressPeers {
  /** The project's own env namespaces (this one included): every pod, any port. */
  projectNamespaces: readonly string[];
  /** Projects whose runner pods may connect to every pod: the project itself. */
  runnerProjects: readonly string[];
  /** The services the ingress controller routes to (ingressControllerRoutes). */
  routes: readonly IngressRoute[];
  /** App-link consumers, per producer service. */
  links: readonly AppLinkIngress[];
}

export interface IngressSettings {
  /** Where the platform runs (default `eve`); plain-pod runners run there too. */
  platformNamespace?: string;
  /** Where runner pods run (default `eve-runners`). */
  runnerNamespace?: string;
}

export interface EnvIngressRule {
  from?: NetworkPolicyPeer[];
  ports?: NetworkPolicyPort[];
}

export interface EnvIngressNetworkPolicy {
  apiVersion: 'networking.k8s.io/v1';
  kind: 'NetworkPolicy';
  metadata: { name: string; namespace: string; labels: Record<string, string> };
  spec: {
    podSelector: LabelSelector;
    policyTypes: ['Ingress'];
    ingress: EnvIngressRule[];
  };
}

const NAMESPACE_NAME = 'kubernetes.io/metadata.name';
const WORKLOAD_NAME_LABEL = 'app.kubernetes.io/name';
/** The label the deployer sets on a service's pods (and selects its Service by). */
const COMPONENT_LABEL = 'eve.component';
const byName = (namespace: string): LabelSelector => ({ matchLabels: { [NAMESPACE_NAME]: namespace } });
const tcp = (port: number): NetworkPolicyPort => ({ protocol: 'TCP', port });
const CONTROLLER: NetworkPolicyPeer = {
  namespaceSelector: { matchExpressions: [{ key: NAMESPACE_NAME, operator: 'In', values: [...INGRESS_CONTROLLER_NAMESPACES] }] },
  podSelector: { matchLabels: { ...INGRESS_CONTROLLER_POD_LABELS } },
};

function policy(name: string, namespace: string, podSelector: LabelSelector, ingress: EnvIngressRule[]): EnvIngressNetworkPolicy {
  return {
    apiVersion: 'networking.k8s.io/v1',
    kind: 'NetworkPolicy',
    metadata: { name, namespace, labels: { 'app.kubernetes.io/managed-by': 'eve-horizon', [INGRESS_POLICY_LABEL]: 'env' } },
    spec: { podSelector, policyTypes: ['Ingress'], ingress },
  };
}

function unique<T>(items: readonly T[]): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = JSON.stringify(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/** Runner pods of these projects, in the runner namespace and the platform namespace (plain-pod runners). */
function runnerPeers(projects: readonly string[], settings: IngressSettings): NetworkPolicyPeer[] {
  const platform = settings.platformNamespace ?? DEFAULT_PLATFORM_NAMESPACE;
  const namespaces = [...new Set([settings.runnerNamespace ?? 'eve-runners', platform])];
  return namespaces.flatMap((namespace) => projects.map((projectId) => ({
    namespaceSelector: byName(namespace),
    podSelector: { matchLabels: { [RUNNER_LABELS.runner]: 'true', [RUNNER_LABELS.projectId]: projectId } },
  })));
}

/** What `eve-ingress` admits to every pod, each once. */
function everyPodPeers(peers: IngressPeers, settings: IngressSettings): NetworkPolicyPeer[] {
  return unique([
    {
      namespaceSelector: byName(settings.platformNamespace ?? DEFAULT_PLATFORM_NAMESPACE),
      podSelector: { matchExpressions: [{ key: WORKLOAD_NAME_LABEL, operator: 'In', values: [...PLATFORM_INGRESS_WORKLOADS] }] },
    },
    ...peers.projectNamespaces.map((namespace) => ({ namespaceSelector: byName(namespace) })),
    ...runnerPeers(peers.runnerProjects, settings),
  ]);
}

/**
 * The per-service policies: one for each service the ingress controller
 * routes to or app-link consumers call, keyed by its pods' component label
 * and named after it, in name order.
 */
function servicePolicies(namespace: string, peers: IngressPeers, settings: IngressSettings): EnvIngressNetworkPolicy[] {
  const services = new Map<string, { name: string; routePorts: number[]; links: AppLinkIngress[] }>();
  const entry = (service: string) => {
    let component: string;
    try {
      component = toK8sLabelValue(service, 'component');
    } catch {
      return null; // a name the deployer could run no pods under
    }
    let found = services.get(component);
    if (!found) {
      found = { name: `${ENV_INGRESS_SERVICE_POLICY_PREFIX}${toK8sName(component, 'component')}`, routePorts: [], links: [] };
      services.set(component, found);
    }
    return found;
  };
  for (const route of peers.routes) entry(route.service)?.routePorts.push(route.port);
  for (const link of peers.links) entry(link.service)?.links.push(link);

  return [...services.entries()]
    .sort(([, a], [, b]) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    .map(([component, { name, routePorts, links }]) => {
      const rules: EnvIngressRule[] = [];
      if (routePorts.length > 0) rules.push({ from: [CONTROLLER], ports: [...new Set(routePorts)].map(tcp) });
      // One rule per link port, so a link's callers reach only its port.
      const byPort = new Map<number | null, AppLinkIngress[]>();
      for (const link of links) byPort.set(link.port, [...byPort.get(link.port) ?? [], link]);
      for (const [port, group] of byPort) {
        const from = unique([
          ...group.flatMap((link) => link.namespaces.map((ns) => ({ namespaceSelector: byName(ns) }))),
          ...runnerPeers([...new Set(group.flatMap((link) => link.runnerProjects))], settings),
        ]);
        if (from.length > 0) rules.push(port === null ? { from } : { from, ports: [tcp(port)] });
      }
      return policy(name, namespace, { matchLabels: { [COMPONENT_LABEL]: component } }, rules);
    })
    .filter((p) => p.spec.ingress.length > 0);
}

/**
 * The ingress policies an env namespace should hold under a profile, in the
 * order to write them (the per-service allows before `eve-ingress`, so a
 * move to `strict` from an earlier, wider set never refuses their callers).
 * Any other Eve ingress policy there is to be deleted after. Under `audit`
 * and `legacy`, none.
 */
export function envIngressPolicies(
  namespace: string,
  profile: SecurityProfile,
  peers: IngressPeers,
  settings: IngressSettings = {},
): EnvIngressNetworkPolicy[] {
  if (profile !== 'strict') return [];
  return [
    ...servicePolicies(namespace, peers, settings),
    policy(ENV_INGRESS_POLICY, namespace, {}, [{ from: everyPodPeers(peers, settings) }]),
  ];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

/** A service's ports as the deployer reads them: a number, or the last part of `host:container`. */
function servicePorts(service: Record<string, unknown>): number[] {
  const ports = Array.isArray(service.ports) ? service.ports : [];
  return ports
    .map((entry) => (typeof entry === 'number' ? entry : typeof entry === 'string' ? parseInt(entry.trim().split(':').pop() ?? '', 10) : NaN))
    .filter((port) => Number.isFinite(port));
}

/**
 * The services of an env (the manifest's, with the env's overrides) that the
 * deployer gives an Ingress, and the port it routes to: public under
 * isPublicIngress (`implicitPublic` is the project's `ports.implicit_public`
 * profile), on `x-eve.ingress.port`, else the first listed port. The
 * deployer's Services target the same port on the pods. Services it runs no
 * pods for (external, managed databases) and job services are left out.
 */
export function ingressControllerRoutes(
  services: Record<string, unknown> | null | undefined,
  implicitPublic: SecurityProfile,
): IngressRoute[] {
  const routes: IngressRoute[] = [];
  for (const [service, definition] of Object.entries(services ?? {})) {
    if (!isRecord(definition)) continue;
    const xeve = definition['x-eve'] ?? definition.x_eve;
    if (isRecord(xeve) && (xeve.external || xeve.connection_url || xeve.role === 'job' || xeve.role === 'managed_db')) continue;
    if (!isPublicIngress(definition, implicitPublic)) continue;
    const block = serviceIngressBlock(definition);
    const port = typeof block?.port === 'number' ? block.port : servicePorts(definition)[0];
    if (Number.isInteger(port) && port > 0 && port < 65536) routes.push({ service, port });
  }
  return routes;
}
