import { Logger } from '@nestjs/common';
import * as dns from 'node:dns/promises';
import * as net from 'node:net';
import yaml from 'yaml';
import {
  appLinkSubscriptionQueries,
  environmentQueries,
  governingSecurityProfile,
  managedDbQueries,
  orgQueries,
  projectManifestQueries,
  projectQueries,
  securityQueries,
  systemSettingsQueries,
  type Db,
} from '@eve/db';
import {
  DEFAULT_PLATFORM_NAMESPACE,
  DEFAULT_RUNNER_NAMESPACE,
  EGRESS_POLICY_LABEL,
  EGRESS_RULE,
  NETWORK_PRIVATE_CIDRS_SETTING,
  RUNNER_PROJECT_LABEL,
  deriveNamespace,
  envEgressPolicies,
  parseCidrList,
  runnerEgressPolicies,
  type EgressExtras,
  type EgressNetworkPolicy,
  type EgressSettings,
  type SecurityProfile,
} from '@eve/shared';

/** What EgressPolicies needs of the Kubernetes API (K8sService). */
export interface NetworkPolicyApi {
  /** Create or replace; false when the cluster already holds it unchanged. */
  applyNetworkPolicy(policy: EgressNetworkPolicy): Promise<boolean>;
  deleteNetworkPolicy(namespace: string, name: string): Promise<void>;
  listNetworkPolicies(namespace: string, labelSelector: string): Promise<Array<{ name: string; labels: Record<string, string> }>>;
  /** Null when the namespace does not exist. */
  getNamespaceLabels(name: string): Promise<Record<string, string> | null>;
}

export interface EgressEnvRef {
  id: string;
  projectId: string;
  name: string;
  /** The env's Kubernetes namespace. */
  namespace: string;
}

export interface EgressSync {
  profile: SecurityProfile;
  /** Policies written (created or changed); unchanged ones are not. */
  applied: string[];
  /** Eve policies of the same kind deleted because the profile no longer wants them. */
  removed: string[];
}

export interface NetworkReconcileReport {
  environments: {
    reconciled: number;
    /** Envs never deployed, or whose namespace is gone: nothing to write. */
    without_namespace: number;
    applied: number;
    removed: number;
    failed: Array<{ environment_id: string; error: string }>;
  };
  runners: {
    projects: number;
    applied: number;
    removed: number;
    /** Runner policies of projects that no longer exist. */
    orphans_removed: number;
    failed: Array<{ project_id: string; error: string }>;
  };
}

type LoggerLike = Pick<Logger, 'log' | 'warn'>;

const ENV_SELECTOR = `${EGRESS_POLICY_LABEL}=env`;
const RUNNER_SELECTOR = `${EGRESS_POLICY_LABEL}=runner`;
const runnerSelector = (projectId: string) => `${RUNNER_SELECTOR},${RUNNER_PROJECT_LABEL}=${projectId}`;
const CLUSTER_HOST = /^[a-z0-9-]+\.([a-z0-9-]+)\.svc(?:\.cluster\.local)?\.?$/i;

/**
 * egress.default_deny in the cluster: writes each env namespace's egress
 * policies and each project's runner policies from what the database says
 * the project needs (managed databases, app-link producers, its own envs),
 * and keeps them in line with the project's profile. The deployer calls it
 * at each deploy, dispatch before a runner pod starts, and
 * `POST /network/reconcile` for a profile change or
 * `eve system security reconcile`.
 */
export class EgressPolicies {
  private readonly logger: LoggerLike;
  private readonly resolveHost: (host: string) => Promise<string[]>;
  private readonly settingsQueries: ReturnType<typeof systemSettingsQueries>;
  private readonly projects: ReturnType<typeof projectQueries>;
  private readonly orgs: ReturnType<typeof orgQueries>;
  private readonly envs: ReturnType<typeof environmentQueries>;
  private readonly managedDb: ReturnType<typeof managedDbQueries>;
  private readonly appLinks: ReturnType<typeof appLinkSubscriptionQueries>;
  private readonly manifests: ReturnType<typeof projectManifestQueries>;
  private readonly security: ReturnType<typeof securityQueries>;

  constructor(
    private readonly db: Db,
    private readonly k8s: NetworkPolicyApi,
    options: { logger?: LoggerLike; resolveHost?: (host: string) => Promise<string[]> } = {},
  ) {
    this.logger = options.logger ?? new Logger(EgressPolicies.name);
    this.resolveHost = options.resolveHost
      ?? (async (host) => (await dns.lookup(host, { all: true, family: 4 })).map((entry) => entry.address));
    this.settingsQueries = systemSettingsQueries(db);
    this.projects = projectQueries(db);
    this.orgs = orgQueries(db);
    this.envs = environmentQueries(db);
    this.managedDb = managedDbQueries(db);
    this.appLinks = appLinkSubscriptionQueries(db);
    this.manifests = projectManifestQueries(db);
    this.security = securityQueries(db);
  }

  /** The profile egress.default_deny runs under for a project (stamps honoured). */
  profile(projectId: string): Promise<SecurityProfile> {
    return governingSecurityProfile(this.db, { projectId, governing: 'project', rule: EGRESS_RULE });
  }

  /** Bring an env namespace's egress policies in line with the project's profile. */
  async applyEnv(env: EgressEnvRef, profile?: SecurityProfile): Promise<EgressSync> {
    const resolved = profile ?? await this.profile(env.projectId);
    const desired = resolved === 'legacy'
      ? []
      : envEgressPolicies(env.namespace, resolved, await this.envExtras(env), await this.settings());
    return { profile: resolved, ...(await this.sync(env.namespace, ENV_SELECTOR, desired)) };
  }

  /** Bring a project's runner policies in line with its profile, in each runner namespace the cluster has. */
  async applyRunners(projectId: string, profile?: SecurityProfile): Promise<EgressSync> {
    const resolved = profile ?? await this.profile(projectId);
    const settings = await this.settings();
    const extras = resolved === 'legacy' ? {} : await this.runnerExtras(projectId);
    const result: EgressSync = { profile: resolved, applied: [], removed: [] };
    for (const namespace of await this.runnerNamespaces()) {
      const desired = runnerEgressPolicies(namespace, projectId, resolved, extras, settings);
      const synced = await this.sync(namespace, runnerSelector(projectId), desired);
      result.applied.push(...synced.applied.map((name) => `${namespace}/${name}`));
      result.removed.push(...synced.removed.map((name) => `${namespace}/${name}`));
    }
    return result;
  }

  /**
   * Before a runner pod starts: write the project's runner policies only
   * when a runner namespace lacks them or holds a set the profile no longer
   * wants (a profile change, or a project's first job). No writes otherwise.
   */
  async ensureRunnersForDispatch(projectId: string): Promise<'current' | 'written'> {
    const profile = await this.profile(projectId);
    const settings = await this.settings();
    for (const namespace of await this.runnerNamespaces()) {
      const wanted = runnerEgressPolicies(namespace, projectId, profile, {}, settings).map((p) => p.metadata.name).sort();
      const held = (await this.k8s.listNetworkPolicies(namespace, runnerSelector(projectId))).map((p) => p.name).sort();
      if (wanted.join(',') !== held.join(',')) {
        await this.applyRunners(projectId, profile);
        return 'written';
      }
    }
    return 'current';
  }

  /**
   * Every env and runner policy of the projects in scope (all of them by
   * default), with no workload restart. Without an org scope it also deletes
   * the runner policies of projects that no longer exist. One failure does
   * not stop the rest.
   */
  async reconcile(scope: { projectId?: string; orgId?: string } = {}): Promise<NetworkReconcileReport> {
    const report: NetworkReconcileReport = {
      environments: { reconciled: 0, without_namespace: 0, applied: 0, removed: 0, failed: [] },
      runners: { projects: 0, applied: 0, removed: 0, orphans_removed: 0, failed: [] },
    };
    const projects = await this.security.listProjectProfiles({ orgId: scope.orgId, projectId: scope.projectId });

    for (const project of projects) {
      let profile: SecurityProfile;
      try {
        profile = await this.profile(project.id);
      } catch (error) {
        report.runners.failed.push({ project_id: project.id, error: errorMessage(error) });
        continue;
      }
      const org = project.org_id ? await this.orgs.findById(project.org_id) : null;
      for (const env of await this.activeEnvs(project.id)) {
        try {
          if (!org) throw new Error(`org ${project.org_id} not found`);
          const namespace = deriveNamespace(org.slug, project.slug, env.name, env.namespace);
          if ((await this.k8s.getNamespaceLabels(namespace)) === null) {
            report.environments.without_namespace += 1;
            continue;
          }
          const synced = await this.applyEnv({ id: env.id, projectId: project.id, name: env.name, namespace }, profile);
          report.environments.reconciled += 1;
          report.environments.applied += synced.applied.length;
          report.environments.removed += synced.removed.length;
        } catch (error) {
          this.logger.warn(`Could not reconcile the egress policies of environment ${env.id}: ${errorMessage(error)}`);
          report.environments.failed.push({ environment_id: env.id, error: errorMessage(error) });
        }
      }
      try {
        const synced = await this.applyRunners(project.id, profile);
        report.runners.projects += 1;
        report.runners.applied += synced.applied.length;
        report.runners.removed += synced.removed.length;
      } catch (error) {
        this.logger.warn(`Could not reconcile the runner policies of project ${project.id}: ${errorMessage(error)}`);
        report.runners.failed.push({ project_id: project.id, error: errorMessage(error) });
      }
    }

    if (!scope.orgId) {
      const active = new Set(projects.map((p) => p.id));
      for (const namespace of await this.runnerNamespaces()) {
        const selector = scope.projectId ? runnerSelector(scope.projectId) : RUNNER_SELECTOR;
        for (const { name, labels } of await this.k8s.listNetworkPolicies(namespace, selector)) {
          const owner = labels[RUNNER_PROJECT_LABEL];
          if (!owner || active.has(owner)) continue;
          await this.k8s.deleteNetworkPolicy(namespace, name);
          report.runners.orphans_removed += 1;
        }
      }
    }

    this.logger.log(
      `Egress policies reconciled: ${report.environments.reconciled} environment(s) ` +
        `(${report.environments.without_namespace} without a namespace, ${report.environments.failed.length} failed), ` +
        `${report.runners.projects} project runner set(s) (${report.runners.orphans_removed} orphan(s) removed, ` +
        `${report.runners.failed.length} failed)`,
    );
    return report;
  }

  /** Write the desired policies in order, then delete the other Eve policies the selector matches. */
  private async sync(
    namespace: string,
    selector: string,
    desired: EgressNetworkPolicy[],
  ): Promise<{ applied: string[]; removed: string[] }> {
    const existing = await this.k8s.listNetworkPolicies(namespace, selector);
    const applied: string[] = [];
    for (const policy of desired) {
      if (await this.k8s.applyNetworkPolicy(policy)) applied.push(policy.metadata.name);
    }
    const keep = new Set(desired.map((p) => p.metadata.name));
    const removed: string[] = [];
    for (const { name } of existing) {
      if (keep.has(name)) continue;
      await this.k8s.deleteNetworkPolicy(namespace, name);
      removed.push(name);
    }
    return { applied, removed };
  }

  private get platformNamespace(): string {
    return process.env.EVE_K8S_NAMESPACE || DEFAULT_PLATFORM_NAMESPACE;
  }

  /** The runner namespace and, for plain-pod runners, the platform namespace: those that exist. */
  private async runnerNamespaces(): Promise<string[]> {
    const candidates = [...new Set([process.env.EVE_RUNNER_NAMESPACE || DEFAULT_RUNNER_NAMESPACE, this.platformNamespace])];
    const present: string[] = [];
    for (const namespace of candidates) {
      if ((await this.k8s.getNamespaceLabels(namespace)) !== null) present.push(namespace);
    }
    return present;
  }

  private async settings(): Promise<EgressSettings> {
    const row = await this.settingsQueries.get(NETWORK_PRIVATE_CIDRS_SETTING);
    const { cidrs, invalid } = parseCidrList(row?.value);
    if (invalid.length > 0) {
      this.logger.warn(`${NETWORK_PRIVATE_CIDRS_SETTING} has entries that are not IPv4 CIDRs, left out: ${invalid.join(', ')}`);
    }
    return { platformNamespace: this.platformNamespace, privateCidrs: cidrs };
  }

  private async activeEnvs(projectId: string) {
    return (await this.envs.listByProject(projectId)).filter((env) => env.status !== 'terminated');
  }

  /** An env's managed databases and the app-link producers its services call. */
  private async envExtras(env: EgressEnvRef): Promise<EgressExtras> {
    const extras: Required<EgressExtras> = { cidrs: [], namespaces: [] };
    for (const tenant of await this.managedDb.listTenantsByEnv(env.id)) {
      const instance = await this.managedDb.findInstanceById(tenant.instance_id);
      if (!instance) continue;
      const peer = await this.databasePeer(instance.host, instance.port);
      extras.cidrs.push(...peer.cidrs);
      extras.namespaces.push(...peer.namespaces);
    }
    extras.namespaces.push(...await this.producerPeers(env.projectId, [env.name]));
    return extras;
  }

  /** A project's runner pods call its own envs (app APIs, any port) and its app-link producers. */
  private async runnerExtras(projectId: string): Promise<EgressExtras> {
    const project = await this.projects.findById(projectId);
    const org = project ? await this.orgs.findById(project.org_id) : null;
    if (!project || !org) return {};
    const envs = await this.activeEnvs(projectId);
    return {
      namespaces: [
        ...envs.map((env) => ({ namespace: deriveNamespace(org.slug, project.slug, env.name, env.namespace) })),
        ...await this.producerPeers(projectId, envs.map((env) => env.name)),
      ],
    };
  }

  /**
   * A managed database: an IP as a /32, a cluster service as its namespace,
   * any other host name as the /32s it resolves to now (re-resolved at each
   * deploy and reconcile).
   */
  private async databasePeer(host: string, port: number): Promise<Required<EgressExtras>> {
    if (net.isIPv4(host)) return { cidrs: [{ cidr: `${host}/32`, port }], namespaces: [] };
    const cluster = CLUSTER_HOST.exec(host);
    if (cluster) return { cidrs: [], namespaces: [{ namespace: cluster[1].toLowerCase(), ports: [port] }] };
    if (!net.isIPv6(host)) {
      try {
        const addresses = (await this.resolveHost(host)).filter((address) => net.isIPv4(address));
        if (addresses.length > 0) return { cidrs: addresses.map((address) => ({ cidr: `${address}/32`, port })), namespaces: [] };
      } catch (error) {
        this.logger.warn(`Could not resolve managed database host ${host}: ${errorMessage(error)}`);
      }
    }
    this.logger.warn(`Managed database host ${host} has no IPv4 address: under strict, egress.default_deny leaves it unreachable`);
    return { cidrs: [], namespaces: [] };
  }

  /** The namespaces (and service port) of the app-link producers a project consumes, for these env names. */
  private async producerPeers(projectId: string, envNames: string[]): Promise<Array<{ namespace: string; ports?: number[] }>> {
    const peers = new Map<string, { namespace: string; ports?: number[] }>();
    for (const subscription of await this.appLinks.listWithGrants({ consumer_project_id: projectId })) {
      const grant = subscription.api_grant;
      if (!grant || grant.revoked_at || !grant.service_name) continue;
      const producer = await this.projects.findById(grant.producer_project_id);
      const org = producer ? await this.orgs.findById(producer.org_id) : null;
      if (!producer || !org) continue;
      const port = await this.servicePort(producer.id, grant.service_name);
      const ports = port ? [port] : undefined;
      for (const envName of envNames) {
        const producerEnv = subscription.environment_strategy === 'same' ? envName : subscription.producer_env_name;
        if (!producerEnv) continue;
        if (grant.envs.length > 0 && !grant.envs.includes(producerEnv)) continue;
        // Callers address the derived namespace; an env may also hold its own.
        const stored = (await this.envs.findByProjectAndName(producer.id, producerEnv))?.namespace;
        for (const namespace of new Set([
          deriveNamespace(org.slug, producer.slug, producerEnv),
          ...(stored ? [deriveNamespace(org.slug, producer.slug, producerEnv, stored)] : []),
        ])) {
          peers.set(`${namespace}:${port ?? ''}`, { namespace, ports });
        }
      }
    }
    return [...peers.values()];
  }

  /** The container port of a producer's service: its first declared port, from its latest manifest. */
  private async servicePort(projectId: string, serviceName: string): Promise<number | null> {
    try {
      const record = await this.manifests.findLatestByProject(projectId);
      const ports = (yaml.parse(record?.manifest_yaml ?? '') as { services?: Record<string, { ports?: unknown[] }> } | null)
        ?.services?.[serviceName]?.ports;
      const first = Array.isArray(ports) ? ports[0] : undefined;
      const port = typeof first === 'number' ? first : typeof first === 'string' ? parseInt(first.split(':').pop() ?? '', 10) : NaN;
      return Number.isInteger(port) && port > 0 && port < 65536 ? port : null;
    } catch {
      return null;
    }
  }
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
