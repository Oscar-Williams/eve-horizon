import { BadRequestException, Body, ConflictException, Controller, Get, Headers, HttpCode, Inject, Post, UnauthorizedException } from '@nestjs/common';
import {
  RUNNER_INBOUND_KEY_HEADER,
  RUNNER_INBOUND_KEY_SHA256_ENV,
  RunnerApiClient,
  runnerInboundKeyMatches,
  runnerSubmitError,
  withCorrelationContext,
  type RunnerResultReport,
  type RunnerSubmit,
} from '@eve/shared';
import { RUNNER_EXECUTOR, type RunnerExecutor } from './runner.executor.js';
import { RUNNER_SELF_CHECK, type RunnerSelfCheck } from './runner-self-check.js';

/**
 * A runner pod's only routes. /health answers from the process alone. The
 * submit takes one job, authenticated by the inbound key whose hash the pod
 * carries (a warm-pool pod, which carries none, takes its first submit), and
 * runs it in the background. The result goes to the API with the job's own
 * token, and the pod then exits.
 */
@Controller()
export class RunnerController {
  private taken = false;

  constructor(
    @Inject(RUNNER_EXECUTOR) private readonly executor: RunnerExecutor,
    @Inject(RUNNER_SELF_CHECK) private readonly selfCheck: RunnerSelfCheck,
  ) {}

  @Get('health')
  health(): { status: 'ok' } {
    return { status: 'ok' };
  }

  @Post('runner/submit')
  @HttpCode(202)
  submit(
    @Headers(RUNNER_INBOUND_KEY_HEADER) key: string | undefined,
    @Body() body: RunnerSubmit,
  ): { accepted: true; attempt_id: string } {
    const sha256 = process.env[RUNNER_INBOUND_KEY_SHA256_ENV];
    if (sha256 ? !runnerInboundKeyMatches(key, sha256) : !key) {
      throw new UnauthorizedException('Runner inbound key required');
    }
    const error = runnerSubmitError(body);
    if (error) throw new BadRequestException(error);
    if (this.taken) throw new ConflictException('This runner has already taken its job');
    this.taken = true;
    void withCorrelationContext({ jobId: body.job_id, attemptId: body.attempt_id }, () => this.runInBackground(body))
      .catch((err) => console.error('[runner] Background execution failed:', err));
    return { accepted: true, attempt_id: body.attempt_id };
  }

  private async runInBackground(submit: RunnerSubmit): Promise<void> {
    // The job (and its Eve CLI) talks to the API the worker named, with the job's token.
    process.env.EVE_API_URL = submit.api_url;
    const client = new RunnerApiClient({ apiUrl: submit.api_url, jobToken: submit.job_token, jobId: submit.job_id, attemptId: submit.attempt_id });
    let report: RunnerResultReport;
    try {
      const refusal = await this.selfCheck(submit, client);
      report = refusal ?? await this.executor.run(submit, client);
    } catch (err) {
      report = { success: false, exit_code: 1, error: err instanceof Error ? err.message : String(err) };
    }
    try {
      await client.pushResult(report);
    } catch (err) {
      console.error(`[runner] Failed to report the result: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      // One job per pod: the pod ends (Succeeded) once its result is reported.
      if (process.env.EVE_RUNNER_SELF_TERMINATE === '1') setTimeout(() => process.exit(0), 1000);
    }
  }
}
