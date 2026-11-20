/**
 * Runner pods on kubernetes-sigs/agent-sandbox (extensions.agents.x-k8s.io/v1beta1).
 *
 * Eve renders one SandboxTemplate and one SandboxWarmPool per job class, in
 * the runner namespace, from the one runner pod builder. A job takes a pod
 * by a SandboxClaim on its class's pool; job data and the job token arrive
 * only by POST, because a warm pod cannot take per-job env or volumes.
 *
 * Runner pod labels (stable; egress policies select on them):
 *
 * | Label | On | Value |
 * |---|---|---|
 * | `eve.type` | every runner pod | `runner` |
 * | `eve.horizon/runner` | every runner pod (template and plain) | `true` |
 * | `eve.horizon/job-class` | every runner pod | `chat`, `job` or `heavy` |
 * | `eve.horizon/project-id` | a claimed or plain pod | the job's project id |
 * | `eve.horizon/attempt-id` | a claimed or plain pod | the attempt id |
 *
 * A warm pod has only the first three until it is claimed; the claim adds
 * the project and attempt through `additionalPodMetadata`, so `eve.horizon`
 * must be allow-listed in the controller's `agent-sandbox-config`. Egress
 * must fail closed: deny every `eve.horizon/runner` pod by default and allow
 * by project label.
 */

import { buildRunnerPodSpec, type RunnerResources } from './runner-manifests.js';
import type { RunnerPodIsolation } from './runner-pod.js';

export const SANDBOX_API_VERSION = 'extensions.agents.x-k8s.io/v1beta1';
export const SANDBOX_API_GROUP = 'extensions.agents.x-k8s.io';
export const SANDBOX_CLAIM_RESOURCE = `sandboxclaims.${SANDBOX_API_GROUP}`;

export const RUNNER_LABEL_DOMAIN = 'eve.horizon';
export const RUNNER_LABELS = {
  runner: `${RUNNER_LABEL_DOMAIN}/runner`,
  jobClass: `${RUNNER_LABEL_DOMAIN}/job-class`,
  projectId: `${RUNNER_LABEL_DOMAIN}/project-id`,
  attemptId: `${RUNNER_LABEL_DOMAIN}/attempt-id`,
} as const;

export const RUNNER_CLASSES = ['chat', 'job', 'heavy'] as const;
export type RunnerClass = (typeof RUNNER_CLASSES)[number];

export const DEFAULT_RUNNER_NAMESPACE = 'eve-runners';

/** Instance settings that shape the templates. */
export const RUNNER_SETTINGS = {
  runtimeClass: 'runner.runtime_class',
  runtimeOptOut: 'runner.runtime_class_opt_out',
  warmPool: (cls: RunnerClass) => `runner.warm_pool.${cls}`,
} as const;

/** How long a claim outlives its job's timeout before the controller removes it. */
export const CLAIM_SHUTDOWN_MARGIN_SECONDS = 15 * 60;

export function runnerTemplateName(cls: RunnerClass): string {
  return `eve-runner-${cls}`;
}

/**
 * A job's class: `chat` for chat jobs, `heavy` for a job that needs more
 * than the standard pod (a resource class with Kubernetes sizing, from the
 * job's hints or the manifest's defaults, or toolchains or app CLIs copied
 * in by init containers), `job` for the rest. Heavy comes only from those
 * inputs, which the manifest and the instance's resource classes govern (and
 * budgets charge). `hints.runner_class` may name a lighter class (classes run
 * chat, job, heavy, lightest first), never a heavier one: asking for it
 * gains no resources or workspace volume.
 */
export function selectRunnerClass(job: {
  labels?: string[] | null;
  toolchains?: string[] | null;
  appClis?: Array<unknown> | null;
  resourceOverride?: boolean;
  hint?: string | null;
}): RunnerClass {
  let cls: RunnerClass = job.labels?.includes('chat') ? 'chat' : 'job';
  if (job.resourceOverride || (job.toolchains?.length ?? 0) > 0 || (job.appClis?.length ?? 0) > 0) cls = 'heavy';
  const hint = RUNNER_CLASSES.indexOf(job.hint as RunnerClass);
  if (hint >= 0 && hint < RUNNER_CLASSES.indexOf(cls)) cls = RUNNER_CLASSES[hint];
  return cls;
}

export interface RunnerRuntime {
  runtimeClassName?: string;
  nodeSelector?: Record<string, string>;
  tolerations?: Array<{ key: string; operator: 'Equal' | 'Exists'; value?: string; effect?: string }>;
}

const GKE_SANDBOX = { key: 'sandbox.gke.io/runtime', value: 'gvisor' };

/**
 * The runtime class from the instance setting `runner.runtime_class`.
 * `gvisor` also places the pod on GKE Sandbox nodes (their node selector and
 * taint); another value is used as the class name alone.
 */
export function runnerRuntimeFor(setting: string | null | undefined): RunnerRuntime | undefined {
  const value = setting?.trim();
  if (!value || value === 'none') return undefined;
  if (value === 'gvisor') {
    return {
      runtimeClassName: 'gvisor',
      nodeSelector: { [GKE_SANDBOX.key]: GKE_SANDBOX.value },
      tolerations: [{ key: GKE_SANDBOX.key, operator: 'Equal', value: GKE_SANDBOX.value, effect: 'NoSchedule' }],
    };
  }
  return { runtimeClassName: value };
}

/** Requests and limits per class; the job class follows the EVE_K8S_RUNNER_* defaults. */
export function runnerClassResources(cls: RunnerClass): RunnerResources | undefined {
  if (cls === 'chat') return { requests: { cpu: '100m', memory: '512Mi' }, limits: { cpu: '1000m', memory: '2Gi' } };
  if (cls === 'heavy') return { requests: { cpu: '500m', memory: '2Gi' }, limits: { cpu: '4000m', memory: '8Gi' } };
  return undefined;
}

export const HEAVY_WORKSPACE_SIZE = '20Gi';

export interface RunnerTemplateOptions {
  namespace: string;
  image: string;
  runtimeClass?: string | null;
  /** Classes that run without the runtime class (for example a class gVisor cannot run). */
  runtimeOptOut?: RunnerClass[];
  warmPools: Partial<Record<RunnerClass, number>>;
  /** Service account and placement (EVE_RUNNER_* on the worker); no token mount by default. */
  isolation?: RunnerPodIsolation;
  heavyWorkspaceSize?: string;
}

/** The pod labels every runner pod of a class carries. */
export function runnerClassLabels(cls: RunnerClass): Record<string, string> {
  return { 'eve.type': 'runner', [RUNNER_LABELS.runner]: 'true', [RUNNER_LABELS.jobClass]: cls };
}

/** One SandboxTemplate and one SandboxWarmPool per class. */
export function renderRunnerTemplates(opts: RunnerTemplateOptions): Array<Record<string, unknown>> {
  const objects: Array<Record<string, unknown>> = [];
  for (const cls of RUNNER_CLASSES) {
    const runtime = opts.runtimeOptOut?.includes(cls) ? undefined : runnerRuntimeFor(opts.runtimeClass);
    const heavy = cls === 'heavy';
    const podSpec = buildRunnerPodSpec({
      image: opts.image,
      workspace: heavy ? { kind: 'pvc', claimName: 'workspace' } : { kind: 'emptyDir', sizeLimit: '10Gi' },
      resources: runnerClassResources(cls),
      isolation: opts.isolation ?? { automountServiceAccountToken: false },
      runtime,
    });
    // The controller adds a volume for each volumeClaimTemplate; the pod only mounts it.
    if (heavy) podSpec.volumes = (podSpec.volumes as Array<{ name: string }>).filter((v) => v.name !== 'workspace');
    const name = runnerTemplateName(cls);
    objects.push({
      apiVersion: SANDBOX_API_VERSION,
      kind: 'SandboxTemplate',
      metadata: { name, namespace: opts.namespace, labels: { 'app.kubernetes.io/managed-by': 'eve' } },
      spec: {
        podTemplate: { metadata: { labels: runnerClassLabels(cls) }, spec: podSpec },
        ...(heavy ? {
          volumeClaimTemplates: [{
            metadata: { name: 'workspace' },
            spec: { accessModes: ['ReadWriteOnce'], resources: { requests: { storage: opts.heavyWorkspaceSize ?? HEAVY_WORKSPACE_SIZE } } },
          }],
        } : {}),
        // Eve owns runner egress (a default deny for every runner pod, allows by project label).
        networkPolicyManagement: 'Unmanaged',
      },
    });
    objects.push({
      apiVersion: SANDBOX_API_VERSION,
      kind: 'SandboxWarmPool',
      metadata: { name, namespace: opts.namespace, labels: { 'app.kubernetes.io/managed-by': 'eve' } },
      spec: {
        replicas: heavy ? 0 : Math.max(0, Math.trunc(opts.warmPools[cls] ?? 0)),
        sandboxTemplateRef: { name },
        updateStrategy: { type: 'Recreate' },
      },
    });
  }
  return objects;
}

/** The SandboxClaim for one attempt. It carries no env (that would force a cold start, and is refused). */
export function buildRunnerSandboxClaim(opts: {
  name: string;
  namespace: string;
  jobClass: RunnerClass;
  projectId: string;
  attemptId: string;
  jobId: string;
  timeoutSeconds: number;
  now?: Date;
}): Record<string, unknown> {
  const now = opts.now ?? new Date();
  const shutdown = new Date(now.getTime() + (opts.timeoutSeconds + CLAIM_SHUTDOWN_MARGIN_SECONDS) * 1000);
  return {
    apiVersion: SANDBOX_API_VERSION,
    kind: 'SandboxClaim',
    metadata: {
      name: opts.name,
      namespace: opts.namespace,
      labels: { 'eve.type': 'runner-claim' },
      annotations: { 'eve.job_id': opts.jobId, 'eve.attempt_id': opts.attemptId },
    },
    spec: {
      warmPoolRef: { name: runnerTemplateName(opts.jobClass) },
      additionalPodMetadata: { labels: runnerJobLabels(opts) },
      // A safety net when the worker dies mid-job: the controller removes the claim and its pod.
      lifecycle: { shutdownTime: shutdown.toISOString(), shutdownPolicy: 'Delete' },
    },
  };
}

/** A label value: the id itself when it is a valid value (ids are), else a sanitised form. */
function labelValue(value: string): string {
  const normalized = value.replace(/[^A-Za-z0-9-_.]/g, '-').slice(0, 63);
  return normalized.replace(/^[^A-Za-z0-9]+/, '').replace(/[^A-Za-z0-9]+$/, '') || 'unknown';
}

/** The per-job labels a claim adds to its pod (and a plain pod carries). */
export function runnerJobLabels(opts: { projectId: string; attemptId: string; jobClass: RunnerClass }): Record<string, string> {
  return {
    [RUNNER_LABELS.projectId]: labelValue(opts.projectId),
    [RUNNER_LABELS.attemptId]: labelValue(opts.attemptId),
    [RUNNER_LABELS.jobClass]: opts.jobClass,
  };
}
