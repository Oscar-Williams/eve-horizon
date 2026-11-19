/**
 * Runner mode for the agent runtime (EVE_AGENT_RUNTIME_EXECUTION_MODE=runner).
 *
 * The agent runtime builds no runner pod of its own. It hands the invocation
 * to the worker, which prepares the job (every database and internal-API
 * call) and runs it in a credential-free runner pod: one dispatch path for
 * every runner pod. The worker's completion event carries the result.
 */

import { setTimeout as delay } from 'node:timers/promises';
import {
  apiPath,
  getCorrelationHeaders,
  internalAuthHeaders,
  loadConfig,
  parseWorkerUrlMapping,
  type HarnessInvocation,
  type HarnessResult,
} from '@eve/shared';

interface RunnerEvent {
  type: string;
  payload_json: { attemptId: string; result?: HarnessResult; error?: string; exitCode?: number };
}

function workerUrl(): string {
  const config = loadConfig();
  return parseWorkerUrlMapping(config.EVE_WORKER_URLS).get('default-worker') ?? config.WORKER_URL;
}

function failure(attemptId: string, error: string): HarnessResult {
  return { attemptId: attemptId as HarnessResult['attemptId'], success: false, exitCode: 1, error };
}

async function waitForWorkerResult(invocation: HarnessInvocation, signal?: AbortSignal): Promise<HarnessResult> {
  const config = loadConfig();
  const pollMs = parseInt(process.env.EVE_K8S_POLL_INTERVAL_MS ?? '5000', 10);
  const timeoutMs = parseInt(process.env.EVE_K8S_POLL_TIMEOUT_MS ?? '1800000', 10);
  const since = new Date(Date.now() - 60_000).toISOString();
  const url = `${config.EVE_API_URL}${apiPath`/internal/projects/${invocation.projectId}/events`}`
    + `?type=runner.completed,runner.failed&attempt_id=${encodeURIComponent(invocation.attemptId)}`
    + `&since=${encodeURIComponent(since)}&limit=50`;
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    signal?.throwIfAborted();
    try {
      const response = await fetch(url, { signal, headers: { ...internalAuthHeaders(), ...getCorrelationHeaders() } });
      if (response.ok) {
        const events = ((await response.json()) as { data?: RunnerEvent[] }).data ?? [];
        const done = events.find((e) => e.payload_json?.attemptId === invocation.attemptId
          && (e.type === 'runner.completed' || e.type === 'runner.failed'));
        if (done?.type === 'runner.completed' && done.payload_json.result) return done.payload_json.result;
        if (done) return { ...failure(invocation.attemptId, done.payload_json.error || 'Runner failed'), exitCode: done.payload_json.exitCode ?? 1 };
      }
    } catch (err) {
      signal?.throwIfAborted();
      console.warn(`[runner-forward] Poll failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    await delay(pollMs, undefined, { signal });
  }
  return failure(invocation.attemptId, `Runner timed out after ${timeoutMs}ms`);
}

/** Hand an invocation to the worker's runner path and wait for its result. */
export async function forwardInvocationToWorker(invocation: HarnessInvocation, signal?: AbortSignal): Promise<HarnessResult> {
  signal?.throwIfAborted();
  try {
    const response = await fetch(`${workerUrl()}/invoke`, {
      method: 'POST',
      signal,
      headers: { 'content-type': 'application/json', ...internalAuthHeaders(), ...getCorrelationHeaders() },
      body: JSON.stringify(invocation),
    });
    if (!response.ok) {
      return failure(invocation.attemptId, `Worker returned ${response.status}: ${await response.text().catch(() => '')}`);
    }
    const accepted = (await response.json()) as { accepted?: boolean; error?: string };
    if (!accepted.accepted) return failure(invocation.attemptId, `Worker rejected job: ${accepted.error ?? 'unknown'}`);
  } catch (err) {
    if (signal?.aborted) throw signal.reason ?? err;
    return failure(invocation.attemptId, `Failed to reach the worker: ${err instanceof Error ? err.message : String(err)}`);
  }
  return waitForWorkerResult(invocation, signal);
}
