import * as path from 'node:path';
import type { HarnessInvocation, RunnerApiClient, RunnerResultReport, RunnerSubmit } from '@eve/shared';
import { InvokeService } from '../invoke/invoke.service.js';
import { ScriptExecutorService } from '../script-executor/script-executor.service.js';

export const RUNNER_EXECUTOR = 'RUNNER_EXECUTOR';

/** Runs one submitted job and returns the result the runner reports. */
export interface RunnerExecutor {
  run(submit: RunnerSubmit, client: RunnerApiClient): Promise<RunnerResultReport>;
}

/**
 * Execution logs, pushed to the attempt's logs route in batches. Appending
 * never blocks the harness; `flush` drains what is queued before the result
 * is reported.
 */
export class RunnerLogSink {
  private queue: Array<{ type: string; content: Record<string, unknown> }> = [];
  private sending: Promise<void> = Promise.resolve();
  private timer: NodeJS.Timeout | null = null;

  constructor(private readonly client: RunnerApiClient, private readonly maxBatch = 100, private readonly intervalMs = 250) {}

  appendLog(type: string, content: Record<string, unknown>): void {
    this.queue.push({ type, content });
    if (this.queue.length >= this.maxBatch) {
      void this.send();
    } else if (!this.timer) {
      this.timer = setTimeout(() => { this.timer = null; void this.send(); }, this.intervalMs);
    }
  }

  private send(): Promise<void> {
    const batch = this.queue.splice(0, this.maxBatch);
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
