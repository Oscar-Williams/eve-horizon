/**
 * The one runner pod builder.
 *
 * Every runner pod Eve starts (a plain pod, or the pod template of a
 * SandboxTemplate) comes from here, so they share one security posture:
 *
 * - no platform credential: no database URL, no internal key or its hash, no
 *   forwarded `EVE_WORKER_*` or `EVE_HARNESS_*` settings. The worker resolves
 *   everything the job needs and POSTs it (runner-protocol.ts);
 * - the runner entrypoint (`dist/runner/main.js`), never the worker app;
 * - non-root, no privilege escalation, every capability dropped, the runtime
 *   seccomp profile and no service account token;
 * - an org filesystem only when the job asks for one, read-only unless it
 *   writes;
 * - a runner that refuses to start unless its process is non-dumpable, so
 *   job processes (same UID) cannot read its environment. Runner pods get
 *   that from a preloaded library (`RUNNER_NODUMP_LIBRARY`) rather than the
 *   image's execute-only binaries, which gVisor cannot load.
 *
 * Pod labels P2-3's egress policies select on are documented in
 * docs/system/job-execution.md ("Runner pod labels").
 */

import { RUNNER_INBOUND_KEY_SHA256_ENV, RUNNER_POOL_KEY_SHA256_ENV, RUNNER_PORT } from './runner-protocol.js';
import { resolveRunnerPodIsolation, type RunnerPodIsolation } from './runner-pod.js';

/*
 * How a runner pod starts: tini, the image's entrypoint script, then the
 * runner (`exec "$@"`), all from the image's ordinary, readable binaries.
 *
 * The long-lived services start from execute-only copies
 * (`/usr/local/libexec/eve-tini`, `eve-node`), which the kernel runs
 * non-dumpable. gVisor, which sandboxes runner pods, cannot load an
 * execute-only binary, so each of these processes instead loads
 * `RUNNER_NODUMP_LIBRARY` (LD_PRELOAD), which marks it non-dumpable as it
 * starts and exits if it cannot. The runner still checks the result and
 * refuses to start unprotected (EVE_REQUIRE_ENVIRON_PROTECTION). Job
 * processes never load the library: their environments are allowlists.
 */
export const RUNNER_CONTAINER_COMMAND = ['/usr/bin/tini', '--', '/usr/local/bin/eve-worker-entrypoint'];
export const RUNNER_CONTAINER_ARGS = ['/usr/local/bin/node', '--disable-sigusr1', 'dist/runner/main.js'];
export const RUNNER_NODUMP_LIBRARY = '/usr/local/lib/eve/eve-nodump.so';

export const RUNNER_UID = 1000;

export interface RunnerResources {
  requests?: { cpu?: string; memory?: string };
  limits?: { cpu?: string; memory?: string };
}

export interface RunnerPodOptions {
  name?: string;
  namespace?: string;
  image: string;
  labels?: Record<string, string>;
  annotations?: Record<string, string>;
  /** SHA-256 of the pod's inbound key; omitted for warm-pool templates. */
  inboundKeySha256?: string;
  /** SHA-256 of the worker's pool key; warm-pool templates only. */
  poolKeySha256?: string;
  /** The job's workspace: a claim (plain pods), or a pod-local emptyDir. */
  workspace: { kind: 'pvc'; claimName: string } | { kind: 'emptyDir'; sizeLimit?: string };
  /** The org filesystem claim; null or omitted mounts none. */
  orgFs?: { readOnly: boolean; claimName?: string } | null;
  toolchains?: string[];
  appClis?: Array<{ name: string; image: string }>;
  resources?: RunnerResources;
  activeDeadlineSeconds?: number;
  /** Service account, token mount and placement; read from EVE_RUNNER_* when omitted. */
  isolation?: RunnerPodIsolation;
  /** A runtime class (for example gvisor), with the node selector and toleration it needs. */
  runtime?: {
    runtimeClassName?: string;
    nodeSelector?: Record<string, string>;
    tolerations?: Array<{ key: string; operator: 'Equal' | 'Exists'; value?: string; effect?: string }>;
  };
  imagePullPolicy?: 'Always' | 'IfNotPresent' | 'Never';
  toolchainImagePrefix?: string;
  toolchainImageTag?: string;
}

type EnvVar = { name: string; value: string };

export const DEFAULT_ORG_FS_CLAIM = 'eve-org-fs-org-default';

function pullPolicy(opts: RunnerPodOptions): 'Always' | 'IfNotPresent' | 'Never' {
  return opts.imagePullPolicy ?? (process.env.EVE_K8S_IMAGE_PULL_POLICY as 'Always' | 'IfNotPresent' | 'Never' | undefined) ?? 'IfNotPresent';
}

/** The pod spec of a runner pod. */
export function buildRunnerPodSpec(opts: RunnerPodOptions): Record<string, any> {
  // Pod affinity (EVE_RUNNER_POD_AFFINITY_*) places a pod that mounts the
  // ReadWriteOnce org filesystem beside the pod holding it, in the platform
  // namespace; no other runner pod has anything to be co-located with.
  const { affinity, ...isolation } = opts.isolation ?? resolveRunnerPodIsolation();
  const toolchains = [...new Set(opts.toolchains ?? [])];
  const appClis = opts.appClis ?? [];
  const prefix = opts.toolchainImagePrefix ?? process.env.EVE_TOOLCHAIN_IMAGE_PREFIX ?? 'eve-horizon/toolchain-';
  const tag = opts.toolchainImageTag ?? process.env.EVE_TOOLCHAIN_IMAGE_TAG ?? 'local';
  const policy = pullPolicy(opts);
  const initSecurity = { runAsNonRoot: true, allowPrivilegeEscalation: false, capabilities: { drop: ['ALL'] } };

  const env: EnvVar[] = [
    { name: 'WORKER_PORT', value: String(RUNNER_PORT) },
    { name: 'EVE_RUNNER_SELF_TERMINATE', value: '1' },
    { name: 'EVE_WORKSPACE_ROOT', value: '/opt/eve/workspaces' },
    { name: 'EVE_CACHE_ROOT', value: '/opt/eve/cache' },
    { name: 'EVE_STATE_ROOT', value: '/opt/eve/state' },
    { name: 'EVE_TOOLCHAIN_ROOT', value: '/opt/eve/toolchains' },
    { name: 'EVE_TOOLCHAIN_INIT_MOUNTED', value: 'true' },
    { name: 'EVE_REQUIRE_ENVIRON_PROTECTION', value: 'true' },
    { name: 'LD_PRELOAD', value: RUNNER_NODUMP_LIBRARY },
  ];
  if (opts.inboundKeySha256) env.push({ name: RUNNER_INBOUND_KEY_SHA256_ENV, value: opts.inboundKeySha256 });
  if (opts.poolKeySha256) env.push({ name: RUNNER_POOL_KEY_SHA256_ENV, value: opts.poolKeySha256 });
  if (opts.orgFs) env.push({ name: 'EVE_ORG_FS_ROOT', value: '/org' });
  if (toolchains.length > 0) {
    env.push({ name: 'EVE_TOOLCHAIN_PATHS', value: toolchains.map((tc) => `/opt/eve/toolchains/${tc}/bin`).join(':') });
  }
  if (appClis.length > 0) {
    env.push({ name: 'EVE_APP_CLI_PATHS', value: appClis.map((cli) => `/opt/eve/app-cli/${cli.name}/bin`).join(':') });
  }

  const initContainers = [
    ...toolchains.map((tc) => ({
      name: `tc-${tc}`,
      image: `${prefix}${tc}:${tag}`,
      imagePullPolicy: policy,
      command: ['sh', '-ec', `cp -R /toolchain/. /opt/eve/toolchains/${tc}/`],
      securityContext: initSecurity,
      volumeMounts: [{ name: 'toolchains', mountPath: `/opt/eve/toolchains/${tc}`, subPath: tc }],
    })),
    ...appClis.map((cli) => ({
      name: `cli-${cli.name}`,
      image: cli.image,
      imagePullPolicy: policy,
      command: ['sh', '-ec', `cp -R /cli/. /opt/eve/app-cli/${cli.name}/`],
      securityContext: initSecurity,
      volumeMounts: [{ name: 'app-cli', mountPath: `/opt/eve/app-cli/${cli.name}`, subPath: cli.name }],
    })),
  ];

  const volumeMounts: Array<Record<string, unknown>> = [{ name: 'workspace', mountPath: '/opt/eve/workspaces' }];
  const volumes: Array<Record<string, unknown>> = [
    opts.workspace.kind === 'pvc'
      ? { name: 'workspace', persistentVolumeClaim: { claimName: opts.workspace.claimName } }
      : { name: 'workspace', emptyDir: opts.workspace.sizeLimit ? { sizeLimit: opts.workspace.sizeLimit } : {} },
  ];
  if (opts.orgFs) {
    volumeMounts.push({ name: 'org-fs', mountPath: '/org', readOnly: opts.orgFs.readOnly });
    volumes.push({ name: 'org-fs', persistentVolumeClaim: { claimName: opts.orgFs.claimName ?? DEFAULT_ORG_FS_CLAIM, readOnly: opts.orgFs.readOnly } });
  }
  if (toolchains.length > 0) {
    volumeMounts.push({ name: 'toolchains', mountPath: '/opt/eve/toolchains' });
    volumes.push({ name: 'toolchains', emptyDir: {} });
  }
  if (appClis.length > 0) {
    volumeMounts.push({ name: 'app-cli', mountPath: '/opt/eve/app-cli' });
    volumes.push({ name: 'app-cli', emptyDir: {} });
  }
  const runtimeNodeSelector = opts.runtime?.nodeSelector;
  const runtimeTolerations = opts.runtime?.tolerations;
  return {
    ...(opts.activeDeadlineSeconds ? { activeDeadlineSeconds: opts.activeDeadlineSeconds } : {}),
    restartPolicy: 'Never',
    enableServiceLinks: false,
    terminationGracePeriodSeconds: 10,
    // Job code needs no Kubernetes API: no token, no platform service account.
    ...isolation,
    ...(opts.orgFs && affinity ? { affinity } : {}),
    automountServiceAccountToken: isolation.automountServiceAccountToken === true,
    ...(opts.runtime?.runtimeClassName ? { runtimeClassName: opts.runtime.runtimeClassName } : {}),
    ...(runtimeNodeSelector || isolation.nodeSelector
      ? { nodeSelector: { ...(isolation.nodeSelector ?? {}), ...(runtimeNodeSelector ?? {}) } } : {}),
    ...(runtimeTolerations || isolation.tolerations
      ? { tolerations: [...(isolation.tolerations ?? []), ...(runtimeTolerations ?? [])] } : {}),
    securityContext: {
      runAsUser: RUNNER_UID,
      runAsGroup: RUNNER_UID,
      runAsNonRoot: true,
      fsGroup: RUNNER_UID,
      fsGroupChangePolicy: 'OnRootMismatch',
      seccompProfile: { type: 'RuntimeDefault' },
    },
    ...(initContainers.length > 0 ? { initContainers } : {}),
    containers: [{
      name: 'runner',
      image: opts.image,
      imagePullPolicy: policy,
      command: RUNNER_CONTAINER_COMMAND,
      args: RUNNER_CONTAINER_ARGS,
      env,
      securityContext: {
        runAsUser: RUNNER_UID,
        runAsGroup: RUNNER_UID,
        runAsNonRoot: true,
        allowPrivilegeEscalation: false,
        capabilities: { drop: ['ALL'] },
      },
      resources: {
        requests: {
          cpu: opts.resources?.requests?.cpu ?? process.env.EVE_K8S_RUNNER_CPU_REQUEST ?? '100m',
          memory: opts.resources?.requests?.memory ?? process.env.EVE_K8S_RUNNER_MEMORY_REQUEST ?? '256Mi',
        },
        limits: {
          cpu: opts.resources?.limits?.cpu ?? process.env.EVE_K8S_RUNNER_CPU_LIMIT ?? '2000m',
          memory: opts.resources?.limits?.memory ?? process.env.EVE_K8S_RUNNER_MEMORY_LIMIT ?? '2Gi',
        },
      },
      readinessProbe: {
        httpGet: { path: '/health', port: RUNNER_PORT },
        initialDelaySeconds: 1,
        periodSeconds: 2,
        failureThreshold: 30,
      },
      ports: [{ name: 'runner', containerPort: RUNNER_PORT }],
      volumeMounts,
    }],
    volumes,
  };
}

/** A runner Pod manifest. */
export function buildRunnerPod(opts: RunnerPodOptions): { apiVersion: 'v1'; kind: 'Pod'; metadata: Record<string, unknown>; spec: Record<string, any> } {
  return {
    apiVersion: 'v1',
    kind: 'Pod',
    metadata: {
      ...(opts.name ? { name: opts.name } : {}),
      ...(opts.namespace ? { namespace: opts.namespace } : {}),
      labels: opts.labels ?? {},
      ...(opts.annotations ? { annotations: opts.annotations } : {}),
    },
    spec: buildRunnerPodSpec(opts),
  };
}
