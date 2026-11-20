import { Logger } from '@nestjs/common';
import { environmentQueries, orgQueries, projectQueries, type Db } from '@eve/db';
import { ENV_OWNER_LABEL, MANAGED_NAMESPACE_LABEL, deriveNamespace } from '@eve/shared';

/** What the reconcile needs of the Kubernetes API (K8sService). */
export interface ManagedNamespaceApi {
  listNamespaces(labelSelector: string): Promise<Array<{ name: string; labels: Record<string, string> }>>;
  setNamespaceLabels(name: string, labels: Record<string, string | null>): Promise<void>;
  ensureTenantBinding(namespace: string): Promise<'present' | 'created'>;
}

export interface ManagedNamespaceReport {
  /** Env namespaces that got `eve.horizon/managed=true` now. */
  labelled: number;
  /** Managed env namespaces that got the worker's RoleBinding now. */
  bound: number;
  /** Namespaces with `eve.env_id` that match no live environment row: left alone. */
  unmatched: number;
  failed: Array<{ namespace: string; error: string }>;
}

type LoggerLike = Pick<Logger, 'log' | 'warn'>;

/**
 * At worker start-up: label and bind the env namespaces earlier releases
 * created. Those carry `eve.env_id` but neither `eve.horizon/managed` nor
 * the worker's `eve-worker-tenant` RoleBinding, so once the template's
 * cluster-wide rights shrink the worker could not deploy into them.
 *
 * A namespace counts only when its `eve.env_id` names a live environment
 * whose namespace (stored or derived) is this one; anything else is left
 * alone. It is labelled first (the admission policy refuses writes in an
 * unlabelled namespace, and lets the worker add the label only where
 * `eve.env_id` is), then bound. Idempotent: a run with nothing to do
 * writes nothing.
 */
export class ManagedNamespaceReconciler {
  private readonly logger: LoggerLike;
  private readonly envs: ReturnType<typeof environmentQueries>;
  private readonly projects: ReturnType<typeof projectQueries>;
  private readonly orgs: ReturnType<typeof orgQueries>;

  constructor(db: Db, private readonly k8s: ManagedNamespaceApi, logger?: LoggerLike) {
    this.logger = logger ?? new Logger(ManagedNamespaceReconciler.name);
    this.envs = environmentQueries(db);
    this.projects = projectQueries(db);
    this.orgs = orgQueries(db);
  }

  async reconcile(): Promise<ManagedNamespaceReport> {
    const report: ManagedNamespaceReport = { labelled: 0, bound: 0, unmatched: 0, failed: [] };
    for (const namespace of await this.k8s.listNamespaces(ENV_OWNER_LABEL)) {
      try {
        if (!(await this.ownedByLiveEnv(namespace.name, namespace.labels[ENV_OWNER_LABEL]))) {
          report.unmatched += 1;
          continue;
        }
        if (namespace.labels[MANAGED_NAMESPACE_LABEL] !== 'true') {
          await this.k8s.setNamespaceLabels(namespace.name, { [MANAGED_NAMESPACE_LABEL]: 'true' });
          report.labelled += 1;
        }
        if ((await this.k8s.ensureTenantBinding(namespace.name)) === 'created') report.bound += 1;
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        this.logger.warn(`Could not label or bind env namespace ${namespace.name}: ${message}`);
        report.failed.push({ namespace: namespace.name, error: message });
      }
    }
    this.logger.log(
      `Managed namespaces reconciled: ${report.labelled} labelled, ${report.bound} bound, ` +
        `${report.unmatched} left alone (no live environment), ${report.failed.length} failed`,
    );
    return report;
  }

  private async ownedByLiveEnv(namespace: string, envId: string | undefined): Promise<boolean> {
    if (!envId) return false;
    const env = await this.envs.findById(envId);
    if (!env || env.status === 'terminated') return false;
    const project = await this.projects.findById(env.project_id);
    const org = project ? await this.orgs.findById(project.org_id) : null;
    if (!project || !org) return false;
    return deriveNamespace(org.slug, project.slug, env.name, env.namespace) === namespace;
  }
}
