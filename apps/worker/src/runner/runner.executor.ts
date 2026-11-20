import * as path from 'node:path';
import type { HarnessInvocation, RunnerApiClient, RunnerResultReport, RunnerSubmit } from '@eve/shared';
import { InvokeService } from '../invoke/invoke.service.js';
import { ScriptExecutorService } from '../script-executor/script-executor.service.js';

export const RUNNER_EXECUTOR = 'RUNNER_EXECUTOR';

/** Runs one submitted job and returns the result the runner reports. */
export interface RunnerExecutor {
  run(submit: RunnerSubmit, client: RunnerApiClient): Promise<RunnerResultReport>;
}

type LogEntry = { type: string; content: Record<string, unknown> };

/** A batch body stays well under the API's 1 MiB JSON body limit. */
const MAX_BATCH_BYTES = 512 * 1024;
/** One entry larger than this is cut down, with a marker. */
const MAX_ENTRY_BYTES = 256 * 1024;

function entryBytes(entry: LogEntry): number {
  return Buffer.byteLength(JSON.stringify(entry));
}

/**
 * An entry that fits a batch: as it is, or, when too large on its own, with
 * its longest top-level strings cut and `truncated: true` and
 * `original_bytes` added; failing that, a preview of its content.
 */
function fitLogEntry(entry: LogEntry): { entry: LogEntry; bytes: number } {
  const bytes = entryBytes(entry);
  if (bytes <= MAX_ENTRY_BYTES) return { entry, bytes };
  const content: Record<string, unknown> = { ...entry.content, truncated: true, original_bytes: bytes };
  const strings = Object.entries(content)
    .filter((pair): pair is [string, string] => typeof pair[1] === 'string')
    .sort((a, b) => b[1].length - a[1].length);
  for (const [key, value] of strings) {
    const over = entryBytes({ type: entry.type, content }) - MAX_ENTRY_BYTES;
    if (over <= 0) break;
    content[key] = `${value.slice(0, Math.max(0, value.length - over - 64))}...[truncated]`;
  }
  let fitted: LogEntry = { type: entry.type, content };
  if (entryBytes(fitted) > MAX_ENTRY_BYTES) {
    fitted = { type: entry.type, content: { truncated: true, original_bytes: bytes, preview: JSON.stringify(entry.content).slice(0, MAX_ENTRY_BYTES / 8) } };
  }
  return { entry: fitted, bytes: entryBytes(fitted) };
}

/**
 * Execution logs, pushed to the attempt's logs route in batches of at most
 * `maxBatch` entries and well under the API's body limit; an entry too large
 * on its own is cut down rather than lost with its batch. Appending never
 * blocks the harness; `flush` drains what is queued before the result is
 * reported.
 */
export class RunnerLogSink {
  private queue: Array<{ entry: LogEntry; bytes: number }> = [];
  private queuedBytes = 0;
  private sending: Promise<void> = Promise.resolve();
  private timer: NodeJS.Timeout | null = null;

  constructor(private readonly client: RunnerApiClient, private readonly maxBatch = 100, private readonly intervalMs = 250) {}

  appendLog(type: string, content: Record<string, unknown>): void {
    const fitted = fitLogEntry({ type, content });
    this.queue.push(fitted);
    this.queuedBytes += fitted.bytes;
    if (this.queue.length >= this.maxBatch || this.queuedBytes >= MAX_BATCH_BYTES) {
      void this.send();
    } else if (!this.timer) {
      this.timer = setTimeout(() => { this.timer = null; void this.send(); }, this.intervalMs);
    }
  }

  /** The next batch: up to maxBatch entries, within MAX_BATCH_BYTES. */
  private takeBatch(): LogEntry[] {
    let count = 0;
    let bytes = 0;
    while (count < this.queue.length && count < this.maxBatch) {
      const next = this.queue[count].bytes + 1;
      if (count > 0 && bytes + next > MAX_BATCH_BYTES - 64) break;
      bytes += next;
      count += 1;
    }
    this.queuedBytes -= bytes - count;
    return this.queue.splice(0, count).map((item) => item.entry);
  }

  private send(): Promise<void> {
    const batch = this.takeBatch();
    if (batch.length === 0) return this.sending;
    this.sending = this.sending.then(() => this.client.appendLogs(batch)).catch((err) => {
      console.error(`[runner] Failed to push ${batch.length} log entries: ${err instanceof Error ? err.message : String(err)}`);
    });
    return this.sending;
  }

  async flush(): Promise<void> {
    if (this.timer) { clearTimeout(this.timer); this.timer = null; }
    while (this.queue.length > 0) await this.send();
    await this.sending;
  }
}

/** The runner's executor: the worker's own agent and script code, fed by the prepared job. */
export class RunnerJobExecutor implements RunnerExecutor {
  async run(submit: RunnerSubmit, client: RunnerApiClient): Promise<RunnerResultReport> {
    const sink = new RunnerLogSink(client);
    try {
      if (submit.kind === 'agent' && submit.agent) {
        const service = InvokeService.forRunner(submit.agent, client, sink);
        const invocation: HarnessInvocation = {
          ...submit.agent.invocation,
          workspacePath: path.join(process.env.EVE_WORKSPACE_ROOT ?? '/opt/eve/workspaces', submit.attempt_id),
        };
        const result = await service.execute(invocation);
        return {
          success: result.success,
          exit_code: result.exitCode ?? (result.success ? 0 : 1),
          ...(result.error ? { error: result.error } : {}),
          ...(result.resultText !== undefined ? { result_text: result.resultText } : {}),
          ...(result.resultJson !== undefined ? { result_json: result.resultJson } : {}),
          ...(result.durationMs !== undefined ? { duration_ms: result.durationMs } : {}),
          ...(result.tokenInput !== undefined ? { token_input: result.tokenInput } : {}),
          ...(result.tokenOutput !== undefined ? { token_output: result.tokenOutput } : {}),
          ...(service.runnerGitMeta() ? { git: service.runnerGitMeta() } : {}),
        };
      }
      if (submit.kind === 'script' && submit.script) {
        const service = ScriptExecutorService.forRunner({ project_id: submit.project_id, job_token: submit.job_token, script: submit.script }, client, sink);
        const result = await service.execute(submit.job_id, submit.attempt_id);
        return {
          success: result.success,
          exit_code: result.exitCode,
          ...(result.error ? { error: result.error } : {}),
          ...(result.errorCode ? { error_code: result.errorCode } : {}),
          ...(result.stdout !== undefined ? { stdout: result.stdout } : {}),
          ...(result.stderr !== undefined ? { stderr: result.stderr } : {}),
          result_json: { stdout: result.stdout, stderr: result.stderr, exit_code: result.exitCode, ...(result.errorCode ? { error_code: result.errorCode } : {}) },
          duration_ms: result.durationMs,
          ...(service.runnerGitMeta() ? { git: service.runnerGitMeta() } : {}),
        };
      }
      return { success: false, exit_code: 1, error: `Unknown runner job kind: ${String(submit.kind)}` };
    } finally {
      await sink.flush();
    }
  }
}
