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
  createRunnerInboundKey,
  getCorrelationHeaders,
  RUNNER_INBOUND_KEY_HEADER,
  RUNNER_PORT,
  RUNNER_SUBMIT_PATH,
  type HarnessResult,
  type RunnerResultReport,
  type RunnerSubmit,
} from '@eve/shared';
import { createPlainPodBackend, type PodCreatedMeta, type RunnerPodPlan } from './k8s-runner.js';

/** Where a runner pod comes from: a plain pod, or (phase 2) a SandboxClaim. */
export interface RunnerPodBackend {
  /** Create the pod and wait until it is Ready with an IP. */
  start(signal?: AbortSignal): Promise<{ ip: string; podName: string; namespace: string }>;
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
    await deps.submit(pod.ip, submit, opts.inboundKey, signal);
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
  pod: RunnerPodPlan;
  /** The runner's pushed result, read from the database. */
  readResult(attemptId: string): Promise<RunnerResultReport | null>;
  onPodCreated?: (meta: PodCreatedMeta) => Promise<void>;
  onSubmitted?: () => Promise<void>;
  signal?: AbortSignal;
}

/** Run a prepared job in a fresh runner pod and return its recorded outcome. */
export async function dispatchToRunnerPod(submit: RunnerSubmit, opts: DispatchToRunnerPodOptions): Promise<RunnerOutcome> {
  opts.signal?.throwIfAborted();
  const inbound = createRunnerInboundKey();
  const backend = createPlainPodBackend({
    submit,
    plan: opts.pod,
    inboundKeySha256: inbound.sha256,
    onPodCreated: opts.onPodCreated,
  });
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

/** The API URL a runner reports to: the app-facing URL when the instance sets one. */
export function runnerApiUrl(): string {
  const url = process.env.EVE_API_APP_URL || process.env.EVE_API_URL;
  if (!url) throw new Error('EVE_API_URL is required to dispatch a runner pod');
  return url;
}
