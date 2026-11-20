/**
 * Runner pods through kubernetes-sigs/agent-sandbox: a SandboxClaim on the
 * job class's warm pool, in the runner namespace. The worker needs only
 * create, get, watch and delete on sandboxclaims there, get and list on
 * templates and pools, and get on the claimed pod; nothing on sandboxes.
 */

import { setTimeout as delay } from 'node:timers/promises';
import { createHash } from 'node:crypto';
import {
  SANDBOX_API_GROUP,
  SANDBOX_CLAIM_RESOURCE,
  buildRunnerSandboxClaim,
  runnerTemplateName,
  type RunnerClass,
} from '@eve/shared';
import { execKubectl, parseDurationMs } from './k8s-runner.js';
import type { RunnerPodBackend } from './runner-dispatch.js';

/** A claim that is not usable: the caller deletes it and falls back to a plain pod. */
export class SandboxClaimUnavailable extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SandboxClaimUnavailable';
  }
}

const CRD_CACHE_MS = 5 * 60 * 1000;

/** Ready=False reasons (agent-sandbox v1.0.11) a claim does not recover from; others are transient. */
const TERMINAL_CLAIM_REASONS = new Set([
  'TemplateNotFound', 'WarmPoolNotFound', 'InvalidMetadata', 'EnvVarsInjectionRejected',
  'VolumeClaimTemplatesError', 'ClaimExpired', 'SandboxExpired', 'InvalidConfiguration', 'PodFailed',
]);
let crdCache: { present: boolean; at: number } | null = null;
const poolCache = new Map<string, { size: number | null; at: number }>();

/** Whether the agent-sandbox extension CRDs are served (API discovery; needs no RBAC). */
export async function sandboxCrdsPresent(): Promise<boolean> {
  if (process.env.EVE_SANDBOX_BACKEND === 'off') return false;
  if (crdCache && Date.now() - crdCache.at < CRD_CACHE_MS) return crdCache.present;
  let present = false;
  try {
    const result = await execKubectl(['api-resources', `--api-group=${SANDBOX_API_GROUP}`, '-o', 'name']);
    present = result.exitCode === 0 && result.stdout.split(/\s+/).includes(SANDBOX_CLAIM_RESOURCE);
  } catch {
    present = false;
  }
  crdCache = { present, at: Date.now() };
  return present;
}

/**
 * The size of the class's warm pool in the runner namespace, or null when it
 * has not been rendered. A pool of 0 holds no warm pod, so a claim on it
 * would only wait for a cold one: the dispatcher creates the pod directly.
 */
export async function sandboxPoolSize(namespace: string, jobClass: RunnerClass): Promise<number | null> {
  const key = `${namespace}/${jobClass}`;
  const cached = poolCache.get(key);
  if (cached && Date.now() - cached.at < CRD_CACHE_MS) return cached.size;
  const result = await execKubectl(['get', 'sandboxwarmpool', runnerTemplateName(jobClass), `--namespace=${namespace}`, '-o', 'json'])
    .catch(() => ({ exitCode: 1, stdout: '', stderr: '' }));
  let size: number | null = null;
  if (result.exitCode === 0) {
    try {
      const replicas = (JSON.parse(result.stdout) as { spec?: { replicas?: unknown } }).spec?.replicas;
      // The CRD defaults replicas to 1.
      size = typeof replicas === 'number' ? replicas : 1;
    } catch {
      size = null;
    }
  }
  poolCache.set(key, { size, at: Date.now() });
  return size;
}

/** Forget cached discovery (tests, and after a reconcile). */
export function resetSandboxDiscovery(): void {
  crdCache = null;
  poolCache.clear();
}

type ClaimStatus = {
  status?: {
    conditions?: Array<{ type: string; status: string; reason?: string; message?: string }>;
    sandbox?: { name?: string; podIPs?: string[] };
  };
};

export function sandboxClaimName(attemptId: string): string {
  const raw = attemptId.toLowerCase().replace(/[^a-z0-9-]/g, '-');
  const hash = createHash('sha1').update(attemptId).digest('hex').slice(0, 8);
  return `eve-${raw}`.slice(0, 63 - 9).replace(/-+$/, '') + `-${hash}`;
}

export function createSandboxClaimBackend(opts: {
  namespace: string;
  jobClass: RunnerClass;
  submit: { job_id: string; attempt_id: string; project_id: string };
  timeoutSeconds: number;
  onPodCreated?: (meta: { runtime: string; backend: string; pod_name: string; namespace: string; claim: string }) => Promise<void>;
}): RunnerPodBackend & { claimName: string } {
  const claimName = sandboxClaimName(opts.submit.attempt_id);
  let podName: string | null = null;
  const claimTimeoutMs = parseDurationMs(process.env.EVE_SANDBOX_CLAIM_TIMEOUT ?? '10s', 'EVE_SANDBOX_CLAIM_TIMEOUT');
  const pollMs = parseInt(process.env.EVE_SANDBOX_CLAIM_POLL_MS ?? '250', 10);

  return {
    claimName,
    async start(signal) {
      signal?.throwIfAborted();
      const claim = buildRunnerSandboxClaim({
        name: claimName,
        namespace: opts.namespace,
        jobClass: opts.jobClass,
        projectId: opts.submit.project_id,
        attemptId: opts.submit.attempt_id,
        jobId: opts.submit.job_id,
        timeoutSeconds: opts.timeoutSeconds,
      });
      const applied = await execKubectl(['apply', '-f', '-'], JSON.stringify(claim), signal);
      if (applied.exitCode !== 0) throw new SandboxClaimUnavailable(`SandboxClaim ${claimName} was not created: ${applied.stderr || applied.stdout}`);

      const started = Date.now();
      while (Date.now() - started < claimTimeoutMs) {
        const result = await execKubectl(['get', 'sandboxclaim', claimName, `--namespace=${opts.namespace}`, '-o', 'json'], undefined, signal);
        if (result.exitCode === 0) {
          const status = (JSON.parse(result.stdout || '{}') as ClaimStatus).status;
          const ready = status?.conditions?.find((c) => c.type === 'Ready');
          if (ready?.status === 'False' && ready.reason && TERMINAL_CLAIM_REASONS.has(ready.reason)) {
            throw new SandboxClaimUnavailable(`SandboxClaim ${claimName} failed: ${ready.reason}${ready.message ? ` (${ready.message})` : ''}`);
          }
          const ip = status?.sandbox?.podIPs?.[0];
          if (ready?.status === 'True' && ip) {
            podName = status?.sandbox?.name ?? null;
            await opts.onPodCreated?.({ runtime: 'k8s', backend: 'sandbox', pod_name: podName ?? claimName, namespace: opts.namespace, claim: claimName });
            return { ip, podName: podName ?? claimName, namespace: opts.namespace };
          }
        }
        await delay(pollMs, undefined, { signal });
      }
      throw new SandboxClaimUnavailable(`SandboxClaim ${claimName} was not Ready within ${claimTimeoutMs}ms`);
    },

    async podEnded() {
      if (podName) {
        const pod = await execKubectl(['get', 'pod', podName, `--namespace=${opts.namespace}`, '-o', 'json']);
        if (pod.exitCode !== 0) return /not ?found/i.test(pod.stderr);
        const phase = (JSON.parse(pod.stdout) as { status?: { phase?: string } }).status?.phase;
        return phase === 'Succeeded' || phase === 'Failed';
      }
      const claim = await execKubectl(['get', 'sandboxclaim', claimName, `--namespace=${opts.namespace}`, '-o', 'name']);
      return claim.exitCode !== 0;
    },

    async stop() {
      // Deleting the claim removes its sandbox and pod; a failed claim is never left to adopt a pod later.
      try {
        const result = await execKubectl(['delete', 'sandboxclaim', claimName, `--namespace=${opts.namespace}`, '--ignore-not-found=true', '--wait=false']);
        if (result.exitCode !== 0) throw new Error(result.stderr || result.stdout);
      } catch (err) {
        console.error(`Failed to delete SandboxClaim ${claimName}: ${err instanceof Error ? err.message : err}`);
      }
    },
  };
}
