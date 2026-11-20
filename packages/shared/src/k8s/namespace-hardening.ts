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

/** On a namespace where Eve set `enforce` (value: the level), so only Eve's is ever removed. */
export const POD_SECURITY_ENFORCE_ANNOTATION = 'eve.horizon/pod-security-enforce';

/**
 * The Pod Security Standards version `enforce` is pinned to when
 * `EVE_POD_SECURITY_VERSION` is not set: the oldest Kubernetes minor Eve's
 * admission policies support. Pinned, not `latest`, so a cluster upgrade
 * never tightens the checks on running namespaces; set the variable to the
 * cluster's minor to follow it.
 */
export const DEFAULT_POD_SECURITY_VERSION = 'v1.30';

/** `EVE_POD_SECURITY_VERSION` when it is `v1.<minor>`, else the default. */
export function podSecurityVersion(value: string | null | undefined = process.env.EVE_POD_SECURITY_VERSION): string {
  const trimmed = value?.trim() ?? '';
  return /^v1\.\d{1,3}$/.test(trimmed) ? trimmed : DEFAULT_POD_SECURITY_VERSION;
}

export type PodSecurityAdmissionLevel = 'restricted' | 'baseline';

export interface NamespaceMetadata {
  labels: Record<string, string>;
  annotations: Record<string, string>;
}

/** A merge patch of a namespace's labels and annotations (null removes). */
export interface NamespaceMetadataPatch {
  labels: Record<string, string | null>;
  annotations: Record<string, string | null>;
}

const RANK: Record<string, number> = { privileged: 0, baseline: 1, restricted: 2 };

/**
 * An `enforce` Eve set (marked by POD_SECURITY_ENFORCE_ANNOTATION) that is
 * stricter than `level`, lowered to it, as a patch; empty when the namespace
 * has none, it is not stricter, or Eve did not set it. Never raises or adds
 * `enforce`. Used before a deploy's workloads and before a service job.
 */
export function podSecurityEnforceLowering(current: NamespaceMetadata, level: PodSecurityAdmissionLevel): NamespaceMetadataPatch {
  const enforced = current.labels[`${PSA}/enforce`];
  if (!(POD_SECURITY_ENFORCE_ANNOTATION in current.annotations) || enforced === undefined || (RANK[enforced] ?? 0) <= RANK[level]) {
    return { labels: {}, annotations: {} };
  }
  return { labels: { [`${PSA}/enforce`]: level }, annotations: { [POD_SECURITY_ENFORCE_ANNOTATION]: level } };
}

/**
 * isolation.pod_security_admission: what an env namespace's Pod Security
 * labels need at one point of a deploy, as a patch holding only what differs
 * from `current`. `level` is the namespace's level from the render: the
 * least of every service's, service jobs included (`baseline` once one opts
 * out).
 *
 * - `before` the workloads: `warn` and `audit` at the level under `strict`
 *   and `audit`. Under `strict` an `enforce` Eve set that is stricter than
 *   the level is lowered to it now (the release's pods would be refused);
 *   it is never raised or added here. Under `audit` and `legacy` an
 *   `enforce` Eve set (marked by POD_SECURITY_ENFORCE_ANNOTATION) goes, with
 *   its version and mark; one Eve did not set stays.
 * - `after` a rollout that succeeded: under `strict`, `enforce` at the
 *   level, pinned to `version`, marked as Eve's. Raising enforce only then
 *   keeps pods of the old release that do not meet it from being refused
 *   when a node is replaced. Nothing under `audit` and `legacy`.
 */
export function podSecurityAdmissionPatch(input: {
  profile: 'legacy' | 'audit' | 'strict';
  level: PodSecurityAdmissionLevel;
  phase: 'before' | 'after';
  current: NamespaceMetadata;
  version?: string;
}): NamespaceMetadataPatch {
  const { profile, level, phase, current } = input;
  const version = input.version ?? podSecurityVersion();
  const labels: Record<string, string | null> = {};
  const annotations: Record<string, string | null> = {};
  const evesEnforce = POD_SECURITY_ENFORCE_ANNOTATION in current.annotations;

  if (phase === 'after') {
    if (profile === 'strict') {
      Object.assign(labels, {
        [`${PSA}/enforce`]: level,
        [`${PSA}/enforce-version`]: version,
        [`${PSA}/warn`]: level,
        [`${PSA}/audit`]: level,
      });
      annotations[POD_SECURITY_ENFORCE_ANNOTATION] = level;
    }
  } else if (profile === 'strict') {
    Object.assign(labels, { [`${PSA}/warn`]: level, [`${PSA}/audit`]: level });
    const lowering = podSecurityEnforceLowering(current, level);
    Object.assign(labels, lowering.labels);
    Object.assign(annotations, lowering.annotations);
  } else {
    if (profile === 'audit') Object.assign(labels, { [`${PSA}/warn`]: level, [`${PSA}/audit`]: level });
    if (evesEnforce) {
      Object.assign(labels, { [`${PSA}/enforce`]: null, [`${PSA}/enforce-version`]: null });
      annotations[POD_SECURITY_ENFORCE_ANNOTATION] = null;
    }
  }

  const differs = (have: Record<string, string>) => ([key, value]: [string, string | null]) =>
    (value === null ? key in have : have[key] !== value);
  return {
    labels: Object.fromEntries(Object.entries(labels).filter(differs(current.labels))),
    annotations: Object.fromEntries(Object.entries(annotations).filter(differs(current.annotations))),
  };
}
