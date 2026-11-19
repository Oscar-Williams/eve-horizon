/**
 * Plain runner pods through kubectl: the backend used when no SandboxClaim
 * backend is available. The pod comes from the one shared builder
 * (`buildRunnerPod`), so it carries no platform credential and starts the
 * runner entrypoint.
 */

import { setTimeout as delay } from 'node:timers/promises';
import { spawn } from 'child_process';
import { createHash } from 'crypto';
import {
  buildRunnerPod,
  serviceHelperEnv,
  type RunnerResources,
} from '@eve/shared';
import type { RunnerPodBackend } from './runner-dispatch.js';

const DEFAULT_NAMESPACE = 'eve';
const DEFAULT_WORKSPACE_SIZE = '10Gi';

export type RunnerResourceOverrides = RunnerResources;

type ExecResult = { stdout: string; stderr: string; exitCode: number };

export function execKubectl(args: string[], input?: string, signal?: AbortSignal): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const child = spawn('kubectl', ['--request-timeout=10s', ...args], {
      // kubectl needs no service credential; the manifest on stdin carries none either.
      env: serviceHelperEnv(),
      signal,
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk.toString(); });
    child.stderr.on('data', (chunk) => { stderr += chunk.toString(); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ stdout, stderr, exitCode: code ?? 1 }));

    if (input) child.stdin.write(input);
    child.stdin.end();
  });
}

function normalizeNameRaw(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9-]/g, '-');
}

function shortHash(value: string): string {
  return createHash('sha1').update(value).digest('hex').slice(0, 8);
}

export function buildK8sName(base: string, hash: string, limit = 63): string {
  const normalized = normalizeNameRaw(base);
  const suffix = `-${hash}`;
  const maxBase = Math.max(1, limit - suffix.length);
  return `${normalized.slice(0, maxBase)}${suffix}`.slice(0, limit);
}

export function sanitizeLabelValue(value: string): string {
  const normalized = value.toLowerCase().replace(/[^a-z0-9-_.]/g, '-');
  const trimmed = normalized.replace(/^[^a-z0-9]+/, '').replace(/[^a-z0-9]+$/, '');
  return trimmed.slice(0, 63) || 'unknown';
}

export function runnerResourceNames(attemptId: string): { podName: string; pvcName: string } {
  const raw = normalizeNameRaw(attemptId);
  const hash = shortHash(attemptId);
  return { podName: buildK8sName(`eve-runner-${raw}`, hash), pvcName: buildK8sName(`eve-ws-${raw}`, hash) };
}

function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value) throw new Error(`Missing required env: ${name}`);
  return value;
}

/** What a runner pod needs from its job, apart from the job itself (which arrives by POST). */
export interface RunnerPodPlan {
  toolchains?: string[];
  appClis?: Array<{ name: string; image: string }>;
  resources?: RunnerResourceOverrides;
  /** The org filesystem, only when the job's mount spec asks for one. */
  orgFs?: { readOnly: boolean } | null;
  /** Extra pod labels (allow-listed domain), set by the dispatcher. */
  labels?: Record<string, string>;
}

/**
 * The runner pod and its workspace claim, as a kubectl List. Kept as a
 * separate function so the pod's contents can be checked without a cluster.
 */
export function buildRunnerManifests(
  invocation: { jobId: string; attemptId: string; toolchains?: string[]; appClis?: Array<{ name: string; image: string }> },
  namespace: string,
  pvcName: string,
  podName: string,
  resources?: RunnerResourceOverrides,
  inboundKeySha256?: string,
  plan: Pick<RunnerPodPlan, 'orgFs' | 'labels'> = {},
): string {
  const labels = {
    'eve.type': 'runner',
    'eve.job_id': sanitizeLabelValue(invocation.jobId),
    'eve.attempt_id': sanitizeLabelValue(invocation.attemptId),
    ...(plan.labels ?? {}),
  };
  const annotations = { 'eve.job_id': invocation.jobId, 'eve.attempt_id': invocation.attemptId };
  const pvc = {
    apiVersion: 'v1',
    kind: 'PersistentVolumeClaim',
    metadata: { name: pvcName, namespace, labels: { 'eve.type': 'runner', 'eve.job_id': labels['eve.job_id'], 'eve.attempt_id': labels['eve.attempt_id'] }, annotations },
    spec: {
      accessModes: ['ReadWriteOnce'],
      resources: { requests: { storage: process.env.EVE_K8S_WORKSPACE_SIZE ?? DEFAULT_WORKSPACE_SIZE } },
    },
  };
  const pod = buildRunnerPod({
    name: podName,
    namespace,
    image: requiredEnv('EVE_RUNNER_IMAGE'),
    labels,
    annotations,
    inboundKeySha256,
    workspace: { kind: 'pvc', claimName: pvcName },
    orgFs: plan.orgFs ?? null,
    toolchains: invocation.toolchains ?? [],
    appClis: invocation.appClis ?? [],
    resources,
    activeDeadlineSeconds: parseInt(process.env.EVE_K8S_ACTIVE_DEADLINE_SECONDS ?? '7200', 10),
  });
  return JSON.stringify({ apiVersion: 'v1', kind: 'List', items: [pvc, pod] });
}

type InitStatus = { name: string; imageID?: string; state?: { waiting?: { reason?: string; message?: string }; terminated?: { exitCode?: number; message?: string } } };

export function readToolchainInitStatuses(statuses: InitStatus[], toolchains: readonly string[]): Record<string, string> {
  const imageIds: Record<string, string> = {};
  for (const tc of toolchains) {
    const status = statuses.find((entry) => entry.name === `tc-${tc}`);
    if (status?.imageID) imageIds[tc] = status.imageID;
    const waiting = status?.state?.waiting;
    const terminated = status?.state?.terminated;
    if (waiting?.reason === 'ErrImagePull' || waiting?.reason === 'ImagePullBackOff' || (terminated && terminated.exitCode !== 0)) {
      const image = `${process.env.EVE_TOOLCHAIN_IMAGE_PREFIX ?? 'eve-horizon/toolchain-'}${tc}:${process.env.EVE_TOOLCHAIN_IMAGE_TAG ?? 'local'}`;
      throw new Error(`toolchain_unavailable: ${tc} init image ${image} failed: ${waiting?.message ?? terminated?.message ?? waiting?.reason ?? terminated?.exitCode}`);
    }
  }
  return imageIds;
}

export function parseDurationMs(value: string, name: string): number {
  const duration = /^(\d+)(ms|s|m)$/.exec(value);
  if (!duration) throw new Error(`Invalid ${name}: ${value}`);
  return Number(duration[1]) * (duration[2] === 'm' ? 60_000 : duration[2] === 's' ? 1_000 : 1);
}

type PodStatus = {
  status?: {
    phase?: string;
    podIP?: string;
    conditions?: { type: string; status: string }[];
    initContainerStatuses?: InitStatus[];
  };
};

export type PodCreatedMeta = { runtime: string; pod_name: string; namespace: string; backend?: string; toolchains?: Record<string, unknown> };

/** A plain runner pod (with its workspace claim), managed through kubectl. */
export function createPlainPodBackend(opts: {
  submit: { job_id: string; attempt_id: string };
  plan: RunnerPodPlan;
  inboundKeySha256: string;
  namespace?: string;
  onPodCreated?: (meta: PodCreatedMeta) => Promise<void>;
}): RunnerPodBackend {
  const namespace = opts.namespace ?? process.env.EVE_K8S_NAMESPACE ?? DEFAULT_NAMESPACE;
  const { podName, pvcName } = runnerResourceNames(opts.submit.attempt_id);
  const toolchains = [...new Set(opts.plan.toolchains ?? [])];
  const invocation = { jobId: opts.submit.job_id, attemptId: opts.submit.attempt_id, toolchains, appClis: opts.plan.appClis };

  return {
    async start(signal) {
      signal?.throwIfAborted();
      const manifest = buildRunnerManifests(invocation, namespace, pvcName, podName, opts.plan.resources, opts.inboundKeySha256, opts.plan);
      const applied = await execKubectl(['apply', '-f', '-'], manifest, signal);
      if (applied.exitCode !== 0) throw new Error(`Failed to create runner pod: ${applied.stderr || applied.stdout}`);
      await opts.onPodCreated?.({ runtime: 'k8s', backend: 'pod', pod_name: podName, namespace });

      const timeoutMs = parseDurationMs(process.env.EVE_K8S_POD_READY_TIMEOUT ?? '60s', 'EVE_K8S_POD_READY_TIMEOUT');
      const started = Date.now();
      while (Date.now() - started < timeoutMs) {
        const result = await execKubectl(['get', 'pod', podName, `--namespace=${namespace}`, '-o', 'json'], undefined, signal);
        if (result.exitCode !== 0) throw new Error(`Failed to inspect runner pod: ${result.stderr || result.stdout}`);
        const pod = JSON.parse(result.stdout) as PodStatus;
        const imageIds = readToolchainInitStatuses(pod.status?.initContainerStatuses ?? [], toolchains);
        if (pod.status?.conditions?.some((c) => c.type === 'Ready' && c.status === 'True') && pod.status.podIP) {
          if (toolchains.length > 0) {
            const missing = toolchains.find((tc) => !imageIds[tc]);
            if (missing) throw new Error(`toolchain_unavailable: ${missing} init imageID is missing from ready pod ${podName}`);
            await opts.onPodCreated?.({ runtime: 'k8s', backend: 'pod', pod_name: podName, namespace,
              toolchains: { requested: toolchains, resolved: toolchains, image_ids: imageIds } });
          }
          return { ip: pod.status.podIP, podName, namespace };
        }
        await delay(1000, undefined, { signal });
      }
      throw new Error(`Runner pod ${podName} did not become ready within ${timeoutMs}ms`);
    },

    async podEnded() {
      const result = await execKubectl(['get', 'pod', podName, `--namespace=${namespace}`, '-o', 'json']);
      if (result.exitCode !== 0) return /not ?found/i.test(result.stderr);
      const phase = (JSON.parse(result.stdout) as PodStatus).status?.phase;
      return phase === 'Succeeded' || phase === 'Failed';
    },

    async stop(cancelled) {
      try {
        const result = await execKubectl(['delete', 'pod', podName, `--namespace=${namespace}`, '--ignore-not-found=true', '--wait=false',
          ...(cancelled ? ['--grace-period=5'] : [])]);
        if (result.exitCode !== 0) throw new Error(result.stderr || result.stdout);
      } catch (err) {
        console.error(`Failed to delete pod ${podName}: ${err instanceof Error ? err.message : err}`);
      }
      try {
        await execKubectl(['delete', 'pvc', pvcName, `--namespace=${namespace}`, '--ignore-not-found=true', '--wait=false']);
      } catch (err) {
        console.error(`Failed to delete PVC ${pvcName}: ${err instanceof Error ? err.message : err}`);
      }
    },
  };
}
