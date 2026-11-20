/**
 * Running a prepared job in a runner pod.
 *
 * The worker has already done every database and internal-API call the job
 * needs (the submit body). Here it starts a pod, POSTs the submit with the
 * pod's inbound key, and waits. The attempt is recorded only once the
 * runner's pushed result exists AND the pod has ended: a pod that ends with
 * no result fails the attempt, and a pod that outlives its result is removed
 * before the result is returned. The pod is removed whatever happens.
 */

import { setTimeout as delay } from 'node:timers/promises';
import {
  DEFAULT_EVE_API_APP_URL,
  DEFAULT_PLATFORM_NAMESPACE,
  DEFAULT_RUNNER_NAMESPACE,
  HEAVY_WORKSPACE_SIZE,
  createRunnerInboundKey,
  getCorrelationHeaders,
  runnerPoolKey,
  runnerClassLabels,
  runnerClassResources,
  runnerJobLabels,
  runnerRuntimeFor,
  type RunnerClass,
  RUNNER_INBOUND_KEY_HEADER,
  RUNNER_PORT,
  RUNNER_SUBMIT_PATH,
  type HarnessResult,
  type RunnerResultReport,
  type RunnerSubmit,
} from '@eve/shared';
import { createPlainPodBackend, type PodCreatedMeta, type RunnerPodPlan } from './k8s-runner.js';
import {
  SandboxClaimUnavailable,
  createSandboxClaimBackend,
  runnerNamespaceExists,
  sandboxCrdsPresent,
  sandboxPoolSize,
} from './sandbox-claim-backend.js';
import { ensureRunnerEgress } from '../network/runner-egress.js';

/** Where a runner pod comes from: a plain pod, or (phase 2) a SandboxClaim. */
export interface RunnerPodBackend {
  /**
   * Create the pod and wait until it is Ready with an IP. `submitKey` is the
   * key the pod takes a submit with, when it is not the dispatch's own
   * per-pod key (a claimed pod takes the worker's pool key).
   */
  start(signal?: AbortSignal): Promise<{ ip: string; podName: string; namespace: string; submitKey?: string }>;
  /** Whether the pod has terminated (or is gone). */
  podEnded(): Promise<boolean>;
  /** Remove the pod (and anything created with it). Idempotent. */
  stop(cancelled: boolean): Promise<void>;
}

export interface RunnerDispatchDeps {
  backend: RunnerPodBackend;
  submit(ip: string, body: RunnerSubmit, inboundKey: string, signal?: AbortSignal): Promise<void>;
  readResult(attemptId: string): Promise<RunnerResultReport | null>;
  sleep(ms: number, signal?: AbortSignal): Promise<void>;
  now?(): number;
}

export interface RunnerDispatchOptions {
  inboundKey: string;
  pollMs?: number;
  /** How long to wait for a result before giving up (default EVE_K8S_POLL_TIMEOUT_MS or 30 min). */
  timeoutMs?: number;
  /** How long a pod may run on after its result before it is removed. */
  resultGraceMs?: number;
  signal?: AbortSignal;
  /** Called once the runner has accepted the submit. */
  onSubmitted?: () => Promise<void>;
}

export type RunnerOutcome = HarnessResult & { gitMeta?: RunnerResultReport['git']; resultReport?: RunnerResultReport };

function failure(attemptId: string, error: string): RunnerOutcome {
  return { attemptId: attemptId as HarnessResult['attemptId'], success: false, exitCode: 1, error };
}

/** A runner's report as the HarnessResult the worker records. */
export function harnessResultFromReport(attemptId: string, report: RunnerResultReport): RunnerOutcome {
  return {
    attemptId: attemptId as HarnessResult['attemptId'],
    success: report.success,
    exitCode: report.exit_code,
    ...(report.error ? { error: report.error } : {}),
    ...(report.result_text !== undefined ? { resultText: report.result_text } : {}),
    ...(report.result_json !== undefined ? { resultJson: report.result_json as HarnessResult['resultJson'] } : {}),
    ...(report.duration_ms !== undefined ? { durationMs: report.duration_ms } : {}),
    ...(report.token_input !== undefined ? { tokenInput: report.token_input } : {}),
    ...(report.token_output !== undefined ? { tokenOutput: report.token_output } : {}),
    ...(report.git ? { gitMeta: report.git } : {}),
    resultReport: report,
  };
}

export async function runInRunnerPod(submit: RunnerSubmit, deps: RunnerDispatchDeps, opts: RunnerDispatchOptions): Promise<RunnerOutcome> {
  const signal = opts.signal;
  signal?.throwIfAborted();
  const now = deps.now ?? Date.now;
  const pollMs = opts.pollMs ?? 2000;
  const timeoutMs = opts.timeoutMs ?? 30 * 60 * 1000;
  const graceMs = opts.resultGraceMs ?? 30_000;
  try {
    const pod = await deps.backend.start(signal);
    await deps.submit(pod.ip, submit, pod.submitKey ?? opts.inboundKey, signal);
    await opts.onSubmitted?.();

    const deadline = now() + timeoutMs;
    let result: RunnerResultReport | null = null;
    let resultAt = 0;
    let removed = false;
    for (;;) {
      signal?.throwIfAborted();
      if (!result) {
        result = await deps.readResult(submit.attempt_id);
        if (result) resultAt = now();
      }
      signal?.throwIfAborted();
      if (await deps.backend.podEnded()) break;
      if (result && !removed && now() - resultAt > graceMs) {
        await deps.backend.stop(false);
        removed = true;
      }
      if (!result && now() > deadline) return failure(submit.attempt_id, `Runner timed out after ${timeoutMs}ms`);
      await deps.sleep(pollMs, signal);
    }
    // The runner may push its result just before it exits.
    result ??= await deps.readResult(submit.attempt_id);
    if (!result) return failure(submit.attempt_id, 'Runner pod ended without a result');
    return harnessResultFromReport(submit.attempt_id, result);
  } catch (err) {
    if (signal?.aborted) throw signal.reason ?? err;
    return failure(submit.attempt_id, err instanceof Error ? err.message : String(err));
  } finally {
    await deps.backend.stop(Boolean(signal?.aborted));
  }
}

/** POST the submit to the runner, once its /health answers. */
export async function submitToRunner(ip: string, body: RunnerSubmit, inboundKey: string, signal?: AbortSignal): Promise<void> {
  const attempts = parseInt(process.env.EVE_K8S_RUNNER_RETRIES ?? '20', 10);
  const retryMs = parseInt(process.env.EVE_K8S_RUNNER_RETRY_DELAY_MS ?? '1000', 10);
  let healthy = false;
  for (let attempt = 1; attempt <= attempts && !healthy; attempt += 1) {
    try {
      healthy = (await fetch(`http://${ip}:${RUNNER_PORT}/health`, { method: 'GET', signal })).ok;
    } catch {
      signal?.throwIfAborted();
    }
    if (!healthy) await delay(retryMs, undefined, { signal });
  }
  if (!healthy) throw new Error(`Runner not ready after ${attempts} attempts`);

  const response = await fetch(`http://${ip}:${RUNNER_PORT}${RUNNER_SUBMIT_PATH}`, {
    method: 'POST',
    signal,
    headers: { 'content-type': 'application/json', [RUNNER_INBOUND_KEY_HEADER]: inboundKey, ...getCorrelationHeaders() },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw new Error(`Runner submit failed: ${response.status} ${await response.text().catch(() => '')}`);
  }
}

export interface DispatchToRunnerPodOptions {
  pod: RunnerPodPlan & {
    /** The job's class (template and pool): chat, job or heavy. */
    jobClass?: RunnerClass;
    /** The job's timeout, for the claim's shutdown time. */
    timeoutSeconds?: number;
    /** Instance setting runner.runtime_class. */
    runtimeClass?: string | null;
  };
  /** The runner's pushed result, read from the database. */
  readResult(attemptId: string): Promise<RunnerResultReport | null>;
  onPodCreated?: (meta: PodCreatedMeta) => Promise<void>;
  onSubmitted?: () => Promise<void>;
  signal?: AbortSignal;
}

/**
 * The pod for a job. A job that mounts the org filesystem runs as a plain pod
 * in the platform namespace, where the org filesystem claim lives (only under
 * legacy and audit: strict mounts none). Every other job runs in the runner
 * namespace: through a SandboxClaim on its class's warm pool when the
 * agent-sandbox CRDs are present and that pool holds warm pods, else as the
 * identical pod created directly (a pool sized 0 would only make the claim
 * wait for a cold pod). A job with init containers (toolchains, app CLIs) or
 * its own resource class always gets a plain pod: a claim cannot vary the pod.
 */
async function runnerBackendFor(
  submit: RunnerSubmit,
  opts: DispatchToRunnerPodOptions,
  inboundKeySha256: string,
): Promise<RunnerPodBackend> {
  const plan = opts.pod;
  const jobClass = plan.jobClass ?? 'job';
  const runtime = runnerRuntimeFor(plan.runtimeClass);
  const labels = { ...runnerClassLabels(jobClass), ...runnerJobLabels({ projectId: submit.project_id, attemptId: submit.attempt_id, jobClass }) };
  if (plan.orgFs) {
    return createPlainPodBackend({ submit, plan: { ...plan, labels, runtime, workspace: 'pvc' }, inboundKeySha256, onPodCreated: opts.onPodCreated });
  }

  const namespace = process.env.EVE_RUNNER_NAMESPACE || DEFAULT_RUNNER_NAMESPACE;
  const heavy = jobClass === 'heavy';
  const plain = (fallback?: string) => createPlainPodBackend({
    submit,
    plan: {
      ...plan,
      labels,
      runtime,
      workspace: heavy ? 'pvc' : 'emptyDir',
      ...(heavy ? { workspaceSize: process.env.EVE_K8S_WORKSPACE_SIZE ?? HEAVY_WORKSPACE_SIZE } : {}),
      resources: plan.resources ?? runnerClassResources(jobClass),
    },
    namespace,
    inboundKeySha256,
    onPodCreated: opts.onPodCreated && ((meta) => opts.onPodCreated!({ ...meta, ...(fallback ? { fallback } : {}) })),
  });
  const varies = (plan.toolchains?.length ?? 0) > 0 || (plan.appClis?.length ?? 0) > 0 || Boolean(plan.resources);
  // A warm pod takes a submit only with the worker's pool key; without one, claim nothing.
  const poolKey = runnerPoolKey();
  if (varies || !poolKey || !(await sandboxCrdsPresent()) || !(await sandboxPoolSize(namespace, jobClass))) return plain();

  const claim = createSandboxClaimBackend({
    namespace,
    jobClass,
    submit,
    timeoutSeconds: plan.timeoutSeconds ?? Math.ceil(parseInt(process.env.EVE_K8S_POLL_TIMEOUT_MS ?? '1800000', 10) / 1000),
    poolKeySha256: poolKey.sha256,
    onPodCreated: opts.onPodCreated as never,
  });
  let active: RunnerPodBackend = claim;
  return {
    async start(signal) {
      try {
        return { ...(await claim.start(signal)), submitKey: poolKey.key };
      } catch (err) {
        if (signal?.aborted || !(err instanceof SandboxClaimUnavailable)) throw err;
        // A controller outage costs latency, never the job: drop the claim, create the pod directly.
        console.warn(`[runner] ${err.message}; creating the runner pod directly`);
        await claim.stop(false);
        active = plain(err.message);
        return active.start(signal);
      }
    },
    podEnded: () => active.podEnded(),
    stop: (cancelled) => active.stop(cancelled),
  };
}

/** Run a prepared job in a fresh runner pod and return its recorded outcome. */
export async function dispatchToRunnerPod(submit: RunnerSubmit, opts: DispatchToRunnerPodOptions): Promise<RunnerOutcome> {
  opts.signal?.throwIfAborted();
  // egress.default_deny: the project's runner policies (or, under audit and
  // legacy, its allow-all companion) exist before a claim labels a pod with
  // the project or a plain pod starts with it; eve-runner-deny holds until then.
  await ensureRunnerEgress(submit.project_id);
  if (!opts.pod.orgFs) {
    const namespace = process.env.EVE_RUNNER_NAMESPACE || DEFAULT_RUNNER_NAMESPACE;
    if (!(await runnerNamespaceExists(namespace))) {
      return failure(submit.attempt_id, `The runner namespace ${namespace} does not exist, so no runner pod can start. `
        + 'Apply the runner pieces of k8s/base (runner-namespace.yaml, runner-serviceaccount.yaml, runner-rbac.yaml and '
        + 'runner-network-policies.yaml) to the cluster, or set EVE_RUNNER_NAMESPACE on the worker to the namespace that holds them.');
    }
  }
  const inbound = createRunnerInboundKey();
  const backend = await runnerBackendFor(submit, opts, inbound.sha256);
  return runInRunnerPod(submit, {
    backend,
    submit: submitToRunner,
    readResult: opts.readResult,
    sleep: (ms, signal) => delay(ms, undefined, { signal }),
  }, {
    inboundKey: inbound.key,
    pollMs: parseInt(process.env.EVE_K8S_RUNNER_POLL_MS ?? '2000', 10),
    timeoutMs: parseInt(process.env.EVE_K8S_POLL_TIMEOUT_MS ?? '1800000', 10),
    resultGraceMs: parseInt(process.env.EVE_K8S_RUNNER_RESULT_GRACE_MS ?? '30000', 10),
    signal: opts.signal,
    onSubmitted: opts.onSubmitted,
  });
}

/**
 * The API URL a runner reports to: EVE_API_APP_URL, the URL apps get (the
 * API's public port by its cluster name; the same default as the deployer's),
 * never the worker's own EVE_API_URL, which may be a short name the runner
 * namespace cannot resolve or the internal port its egress policy blocks. A
 * single-label host is qualified with the platform namespace, as the
 * deployer does for apps.
 */
export function runnerApiUrl(): string {
  const raw = process.env.EVE_API_APP_URL || DEFAULT_EVE_API_APP_URL;
  try {
    const url = new URL(raw);
    if (url.hostname.includes('.') || url.hostname === 'localhost' || /^[0-9.]+$|:/.test(url.hostname)) return raw;
    url.hostname = `${url.hostname}.${process.env.EVE_K8S_NAMESPACE || DEFAULT_PLATFORM_NAMESPACE}.svc.cluster.local`;
    return url.toString().replace(/\/$/, '');
  } catch {
    return raw;
  }
}
