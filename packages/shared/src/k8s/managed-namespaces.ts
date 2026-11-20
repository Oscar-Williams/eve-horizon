/**
 * The namespaces the worker manages. The worker's cluster-wide rights cover
 * namespaces and RoleBindings only; its rights on workloads, Secrets and
 * policies come from the ClusterRole `eve-worker-tenant`, bound in each
 * namespace it manages. Every namespace it creates carries
 * `eve.horizon/managed=true`, and the template's admission policy
 * (k8s/base/worker-admission-policy.yaml) refuses the worker's writes
 * anywhere else, bar the platform's own static namespaces.
 */

/** On every namespace the worker creates (and, after the start-up reconcile, every env namespace it can match). */
export const MANAGED_NAMESPACE_LABEL = 'eve.horizon/managed';

/** The label env namespaces have carried since before 0.1.328: the environment that owns the namespace. */
export const ENV_OWNER_LABEL = 'eve.env_id';

/** The ClusterRole holding the worker's namespaced rights, bound per namespace. */
export const WORKER_TENANT_ROLE = 'eve-worker-tenant';

/** The worker's service account, in the platform namespace. */
export const WORKER_SERVICE_ACCOUNT = 'eve-worker';

export interface WorkerTenantRoleBinding {
  apiVersion: 'rbac.authorization.k8s.io/v1';
  kind: 'RoleBinding';
  metadata: { name: string; namespace: string; labels: Record<string, string> };
  roleRef: { apiGroup: 'rbac.authorization.k8s.io'; kind: 'ClusterRole'; name: string };
  subjects: Array<{ kind: 'ServiceAccount'; name: string; namespace: string }>;
}

/** The RoleBinding that gives the worker `eve-worker-tenant` in one namespace: the only kind it may create. */
export function workerTenantRoleBinding(namespace: string, platformNamespace: string): WorkerTenantRoleBinding {
  return {
    apiVersion: 'rbac.authorization.k8s.io/v1',
    kind: 'RoleBinding',
    metadata: {
      name: WORKER_TENANT_ROLE,
      namespace,
      labels: { 'app.kubernetes.io/managed-by': 'eve-horizon' },
    },
    roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: WORKER_TENANT_ROLE },
    subjects: [{ kind: 'ServiceAccount', name: WORKER_SERVICE_ACCOUNT, namespace: platformNamespace }],
  };
}
