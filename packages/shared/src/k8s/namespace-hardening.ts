/**
 * Namespace Hardening — Phase 10
 *
 * Pure functions that generate K8s manifest objects for environment namespace
 * hardening: ResourceQuota and LimitRange. Nothing applies them yet (capacity,
 * not isolation). Network isolation is egress.default_deny, in
 * egress-policies.ts.
 *
 * These are plain JS objects that can be serialized to JSON and applied via
 * `kubectl apply -f -` or any K8s client library.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface NamespaceHardeningConfig {
  namespace: string;
  resource_quota?: {
    cpu_requests: string;        // e.g. "4"
    memory_requests: string;     // e.g. "8Gi"
    pvcs: string;                // e.g. "10"
    storage: string;             // e.g. "50Gi"
  };
  limit_range?: {
    default_cpu_request: string; // e.g. "100m"
    default_memory_request: string; // e.g. "256Mi"
    default_cpu_limit: string;   // e.g. "500m"
    default_memory_limit: string;// e.g. "512Mi"
  };
}

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/**
 * Default hardening config for standard environments.
 * Omits `namespace` — the caller supplies that.
 */
export const DEFAULT_HARDENING_CONFIG: Omit<NamespaceHardeningConfig, 'namespace'> = {
  resource_quota: {
    cpu_requests: '4',
    memory_requests: '8Gi',
    pvcs: '10',
    storage: '50Gi',
  },
  limit_range: {
    default_cpu_request: '100m',
    default_memory_request: '256Mi',
    default_cpu_limit: '500m',
    default_memory_limit: '512Mi',
  },
};

// ---------------------------------------------------------------------------
// Generators
// ---------------------------------------------------------------------------

/**
 * Generate a ResourceQuota manifest for the given namespace.
 * Caps aggregate CPU, memory, PVC count, and storage across all pods.
 */
export function generateResourceQuota(config: NamespaceHardeningConfig): object {
  const quota = config.resource_quota ?? DEFAULT_HARDENING_CONFIG.resource_quota!;

  return {
    apiVersion: 'v1',
    kind: 'ResourceQuota',
    metadata: {
      name: 'eve-env-quota',
      namespace: config.namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'eve-horizon',
        'eve.component': 'namespace-hardening',
      },
    },
    spec: {
      hard: {
        'requests.cpu': quota.cpu_requests,
        'requests.memory': quota.memory_requests,
        persistentvolumeclaims: quota.pvcs,
        'requests.storage': quota.storage,
      },
    },
  };
}

/**
 * Generate a LimitRange manifest for the given namespace.
 * Sets default resource requests and limits for containers that don't
 * declare their own, preventing unbounded resource consumption.
 */
export function generateLimitRange(config: NamespaceHardeningConfig): object {
  const limits = config.limit_range ?? DEFAULT_HARDENING_CONFIG.limit_range!;

  return {
    apiVersion: 'v1',
    kind: 'LimitRange',
    metadata: {
      name: 'eve-env-limits',
      namespace: config.namespace,
      labels: {
        'app.kubernetes.io/managed-by': 'eve-horizon',
        'eve.component': 'namespace-hardening',
      },
    },
    spec: {
      limits: [
        {
          type: 'Container',
          defaultRequest: {
            cpu: limits.default_cpu_request,
            memory: limits.default_memory_request,
          },
          default: {
            cpu: limits.default_cpu_limit,
            memory: limits.default_memory_limit,
          },
        },
      ],
    },
  };
}

/**
 * Generate all hardening manifests for a namespace.
 * Returns an array of K8s manifest objects ready for kubectl apply.
 */
export function generateAllHardeningManifests(config: NamespaceHardeningConfig): object[] {
  return [
    generateResourceQuota(config),
    generateLimitRange(config),
  ];
}

/**
 * Merge a partial hardening config (e.g. from system_settings) with defaults.
 * The `namespace` must always be provided explicitly.
 */
export function mergeHardeningConfig(
  namespace: string,
  overrides?: Partial<Omit<NamespaceHardeningConfig, 'namespace'>>,
): NamespaceHardeningConfig {
  return {
    namespace,
    resource_quota: overrides?.resource_quota ?? DEFAULT_HARDENING_CONFIG.resource_quota,
    limit_range: overrides?.limit_range ?? DEFAULT_HARDENING_CONFIG.limit_range,
  };
}

// ---------------------------------------------------------------------------
// isolation.pod_security_admission (rule set 3)
// ---------------------------------------------------------------------------

/** The project rule: Pod Security admission labels on env namespaces. */
export const POD_SECURITY_ADMISSION_RULE = 'isolation.pod_security_admission';

const PSA = 'pod-security.kubernetes.io';

/**
 * The Pod Security labels an env namespace should carry, as a merge patch
 * (null removes a label). `level` is the namespace's level from the render:
 * `restricted`, or `baseline` once a service opts out (isolation.pod_security).
 * - `strict`: `enforce` at that level (version `latest`), with `warn` and `audit`.
 * - `audit`: `warn` and `audit` only.
 * - `legacy`: nothing set.
 * Eve owns `enforce` on env namespaces: under `audit` and `legacy` an
 * `enforce` a strict profile left is removed, so dropping the profile never
 * keeps refusing pods.
 */
export function podSecurityAdmissionLabels(
  profile: 'legacy' | 'audit' | 'strict',
  level: 'restricted' | 'baseline' = 'restricted',
): Record<string, string | null> {
  if (profile === 'strict') {
    return {
      [`${PSA}/enforce`]: level,
      [`${PSA}/enforce-version`]: 'latest',
      [`${PSA}/warn`]: level,
      [`${PSA}/audit`]: level,
    };
  }
  const drop = { [`${PSA}/enforce`]: null, [`${PSA}/enforce-version`]: null };
  return profile === 'audit' ? { ...drop, [`${PSA}/warn`]: level, [`${PSA}/audit`]: level } : drop;
}
