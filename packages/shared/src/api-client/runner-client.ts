/**
 * The runner's only channel to the platform: the push-only attempt routes,
 * called with the attempt's own job token.
 *
 *   POST /jobs/:job/attempts/:attempt/runner/logs
 *   POST /jobs/:job/attempts/:attempt/runner/events
 *   POST /jobs/:job/attempts/:attempt/runner/runtime-meta
 *   POST /jobs/:job/attempts/:attempt/runner/thread-messages
 *   POST /jobs/:job/attempts/:attempt/runner/credential
 *   POST /jobs/:job/attempts/:attempt/runner/result
 *
 * None of them returns platform data. The token stops working when its
 * attempt ends, and reaches no other attempt.
 */

import type { RunnerResultReport } from '../invoke/runner-protocol.js';

export interface RunnerApiClientOptions {
  apiUrl: string;
  jobToken: string;
  jobId: string;
  attemptId: string;
  fetchImpl?: typeof fetch;
}

export class RunnerApiError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = 'RunnerApiError';
  }
}

export class RunnerApiClient {
  private readonly base: string;
  private readonly fetchImpl: typeof fetch;

  constructor(private readonly opts: RunnerApiClientOptions) {
    this.base = `${opts.apiUrl.replace(/\/+$/, '')}/jobs/${encodeURIComponent(opts.jobId)}/attempts/${encodeURIComponent(opts.attemptId)}/runner`;
    this.fetchImpl = opts.fetchImpl ?? ((...args: Parameters<typeof fetch>) => fetch(...args));
  }

  get jobId(): string { return this.opts.jobId; }
  get attemptId(): string { return this.opts.attemptId; }

  private async post(route: string, body: unknown): Promise<void> {
    const response = await this.fetchImpl(`${this.base}/${route}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${this.opts.jobToken}` },
      body: JSON.stringify(body),
    });
    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new RunnerApiError(`runner ${route} failed [${response.status}]: ${text.slice(0, 300)}`, response.status);
    }
  }

  appendLogs(entries: Array<{ type: string; content: Record<string, unknown> }>): Promise<void> {
    return this.post('logs', { entries });
  }

  emitEvent(type: string, payload: Record<string, unknown>): Promise<void> {
    return this.post('events', { type, payload });
  }

  updateRuntimeMeta(meta: Record<string, unknown>): Promise<void> {
    return this.post('runtime-meta', { meta });
  }

  createThreadMessage(message: { thread_id: string; body: string; actor_type: string; actor_id: string; id?: string }): Promise<void> {
    return this.post('thread-messages', message);
  }

  writeBackCredential(key: string, value: string): Promise<void> {
    return this.post('credential', { key, value });
  }

  pushResult(result: RunnerResultReport): Promise<void> {
    return this.post('result', result);
  }
}
