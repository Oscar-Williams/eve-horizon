import { Body, Controller, Headers, HttpCode, HttpStatus, Param, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOperation, ApiParam, ApiTags, type ApiBodyOptions } from '@nestjs/swagger';
import type { RunnerResultReport } from '@eve/shared';
import { Public } from '../auth/auth.decorator.js';
import { RunnerAttemptsService } from './runner-attempts.service.js';

const objectBody = (properties: Record<string, object>, required: string[] = []): ApiBodyOptions => ({
  schema: { type: 'object', properties, ...(required.length ? { required } : {}) } as never,
});

/**
 * Push-only routes for a runner pod, which holds no platform credential. Each
 * takes the attempt's own job token (Authorization: Bearer), checked here
 * rather than by the global guard: it must be a job token bound to the
 * attempt in the path, while that attempt runs.
 */
@ApiTags('jobs')
@ApiBearerAuth()
@ApiParam({ name: 'job_id', type: String })
@ApiParam({ name: 'attempt_id', type: String })
@Controller('jobs/:job_id/attempts/:attempt_id/runner')
export class AttemptsRunnerController {
  constructor(private readonly runner: RunnerAttemptsService) {}

  @Public()
  @Post('logs')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Append a runner's execution log entries to its attempt (the attempt's job token only)" })
  @ApiBody(objectBody({ entries: { type: 'array', items: { type: 'object', properties: { type: { type: 'string' }, content: { type: 'object' } } } } }, ['entries']))
  async appendLogs(
    @Param('job_id') jobId: string,
    @Param('attempt_id') attemptId: string,
    @Headers('authorization') authorization: string | undefined,
    @Body() body: { entries?: unknown },
  ): Promise<void> {
    await this.runner.authorize(jobId, attemptId, authorization);
    await this.runner.appendLogs(attemptId, body?.entries);
  }

  @Public()
  @Post('events')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Emit a runner's resource hydration event for its attempt (the attempt's job token only)" })
  @ApiBody(objectBody({ type: { type: 'string' }, payload: { type: 'object' } }, ['type']))
  async emitEvent(
    @Param('job_id') jobId: string,
    @Param('attempt_id') attemptId: string,
    @Headers('authorization') authorization: string | undefined,
    @Body() body: { type?: unknown; payload?: unknown },
  ): Promise<void> {
    const token = await this.runner.authorize(jobId, attemptId, authorization);
    await this.runner.emitEvent(token, body?.type, body?.payload);
  }

  @Public()
  @Post('runtime-meta')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Report a runner's runtime fields for its attempt (the attempt's job token only)" })
  @ApiBody(objectBody({ meta: { type: 'object' } }, ['meta']))
  async updateRuntimeMeta(
    @Param('job_id') jobId: string,
    @Param('attempt_id') attemptId: string,
    @Headers('authorization') authorization: string | undefined,
    @Body() body: { meta?: unknown },
  ): Promise<void> {
    await this.runner.authorize(jobId, attemptId, authorization);
    await this.runner.updateRuntimeMeta(attemptId, body?.meta);
  }

  @Public()
  @Post('thread-messages')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Post a runner's message to its job's chat or coordination thread (the attempt's job token only)" })
  @ApiBody(objectBody({ thread_id: { type: 'string' }, body: { type: 'string' }, actor_type: { type: 'string', enum: ['agent', 'system'] }, actor_id: { type: 'string' }, id: { type: 'string' }, chat_progress: { type: 'boolean', description: "A chat job's progress, delivered to its chat thread and provider" } }, ['thread_id', 'body', 'actor_type']))
  async createThreadMessage(
    @Param('job_id') jobId: string,
    @Param('attempt_id') attemptId: string,
    @Headers('authorization') authorization: string | undefined,
    @Body() body: Record<string, unknown>,
  ): Promise<void> {
    const token = await this.runner.authorize(jobId, attemptId, authorization);
    await this.runner.createThreadMessage(token, body ?? {});
  }

  @Public()
  @Post('credential')
  @HttpCode(HttpStatus.NO_CONTENT)
  @ApiOperation({ summary: "Write back a refreshed Codex credential for the runner's job (same account only; the attempt's job token only)" })
  @ApiBody(objectBody({ key: { type: 'string', enum: ['CODEX_AUTH_JSON_B64'] }, value: { type: 'string' } }, ['key', 'value']))
  async writeBackCredential(
    @Param('job_id') jobId: string,
    @Param('attempt_id') attemptId: string,
    @Headers('authorization') authorization: string | undefined,
    @Body() body: { key?: unknown; value?: unknown },
  ): Promise<void> {
    const token = await this.runner.authorize(jobId, attemptId, authorization);
    await this.runner.writeBackCredential(token, body?.key, body?.value);
  }

  @Public()
  @Post('result')
  @HttpCode(HttpStatus.CREATED)
  @ApiOperation({ summary: "Report the attempt's result, once (the attempt's job token only)" })
  @ApiBody(objectBody({ success: { type: 'boolean' }, exit_code: { type: 'integer' }, error: { type: 'string' }, result_text: { type: 'string' }, result_json: {}, duration_ms: { type: 'integer' }, token_input: { type: 'integer' }, token_output: { type: 'integer' } }, ['success', 'exit_code']))
  async pushResult(
    @Param('job_id') jobId: string,
    @Param('attempt_id') attemptId: string,
    @Headers('authorization') authorization: string | undefined,
    @Body() body: RunnerResultReport,
  ): Promise<{ recorded: true }> {
    await this.runner.authorize(jobId, attemptId, authorization);
    await this.runner.recordResult(attemptId, body);
    return { recorded: true };
  }
}
