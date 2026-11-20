import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
  Optional,
  UnauthorizedException,
} from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import {
  type Db,
  eventQueries,
  executionLogQueries,
  jobQueries,
  runnerResultQueries,
  threadMessageQueries,
  threadQueries,
} from '@eve/db';
import {
  CODEX_ID_TOKEN_JWKS_URL,
  EVE_MESSAGE_CHAT_MAX_PER_JOB,
  EVE_MESSAGE_CHAT_RATE_LIMIT_MS,
  chatThreadIdOf,
  RUNNER_EVENT_TYPES,
  RUNNER_FINDING_RULES,
  RUNNER_RUNTIME_META_KEYS,
  RUNNER_WRITABLE_CREDENTIALS,
  codexAccountIdOf,
  codexApiKeyOf,
  generateEventId,
  projectThreadId,
  verifiedCodexAccountId,
  type Jwks,
  type RunnerResultReport,
} from '@eve/shared';
import { AuthService } from '../auth/auth.service.js';
import type { AuthUser, JobTokenPayload } from '../auth/auth.types.js';
import { assertJobRunning } from '../auth/job-liveness.js';
import { SecretsService } from '../secrets/secrets.service.js';
import { SecurityService } from '../security/security.service.js';
import { ChatService } from '../chat/chat.service.js';

/** Supplies the Codex token issuer's signing keys (JWKS). */
export const CODEX_JWKS_SOURCE = 'CODEX_JWKS_SOURCE';
export type CodexJwksSource = () => Promise<Jwks>;

const MAX_LOG_ENTRIES = 500;
const MAX_THREAD_MESSAGE = 16 * 1024;

let cachedJwks: { jwks: Jwks; at: number } | null = null;

/** The issuer's published keys, cached for an hour. */
export async function fetchCodexJwks(): Promise<Jwks> {
  if (cachedJwks && Date.now() - cachedJwks.at < 60 * 60 * 1000) return cachedJwks.jwks;
  const url = process.env.EVE_CODEX_JWKS_URL || CODEX_ID_TOKEN_JWKS_URL;
  const response = await fetch(url, { signal: AbortSignal.timeout(10_000) });
  if (!response.ok) throw new Error(`Codex issuer keys unavailable [${response.status}]`);
  const jwks = await response.json() as Jwks;
  if (!Array.isArray(jwks?.keys)) throw new Error('Codex issuer keys are malformed');
  cachedJwks = { jwks, at: Date.now() };
  return jwks;
}

/**
 * The push-only routes a runner pod reports through. Each takes the
 * attempt's own job token: it must be bound to the attempt the path names,
 * and stops working when that attempt ends. Nothing here returns platform
 * data, and job code (which holds the same token) can write only its own
 * attempt's output.
 */
@Injectable()
export class RunnerAttemptsService {
  private readonly logger = new Logger(RunnerAttemptsService.name);
  private readonly jobs: ReturnType<typeof jobQueries>;

  constructor(
    private readonly auth: AuthService,
    @Inject('DB') private readonly db: Db,
    private readonly secrets: SecretsService,
    private readonly security: SecurityService,
    @Optional() @Inject(CODEX_JWKS_SOURCE) private readonly codexJwks: CodexJwksSource = fetchCodexJwks,
    @Optional() private readonly chat?: ChatService,
  ) {
    this.jobs = jobQueries(db);
  }

  /** The caller's job token, bound to this job and attempt, while the attempt runs. */
  async authorize(jobId: string, attemptId: string, authorization: string | undefined): Promise<JobTokenPayload> {
    const match = /^Bearer\s+(\S+)$/i.exec(authorization ?? '');
    if (!match) throw new UnauthorizedException('A job token is required');
    const payload = this.auth.verifyJobToken(match[1]);
    if (!payload.attempt_id) {
      throw new ForbiddenException('Runner routes take a job token bound to its attempt');
    }
    if (payload.job_id !== jobId || payload.attempt_id !== attemptId) {
      throw new ForbiddenException("A job token reaches only its own attempt's runner routes");
    }
    await assertJobRunning(this.jobs, jobId, attemptId);
    return payload;
  }

  async appendLogs(attemptId: string, entries: unknown): Promise<void> {
    if (!Array.isArray(entries) || entries.length > MAX_LOG_ENTRIES) {
      throw new BadRequestException(`entries must be an array of at most ${MAX_LOG_ENTRIES}`);
    }
    const logs = executionLogQueries(this.db);
    for (const entry of entries as Array<{ type?: unknown; content?: unknown }>) {
      if (typeof entry?.type !== 'string' || !entry.type || entry.type.length > 100
        || !entry.content || typeof entry.content !== 'object' || Array.isArray(entry.content)) {
        throw new BadRequestException('each entry needs a type and a content object');
      }
      await logs.appendLog(attemptId, entry.type, entry.content as Record<string, unknown>);
    }
  }

  async emitEvent(token: JobTokenPayload, type: unknown, payload: unknown): Promise<void> {
    if (typeof type !== 'string' || !(RUNNER_EVENT_TYPES as readonly string[]).includes(type)) {
      throw new BadRequestException(`A runner emits only ${RUNNER_EVENT_TYPES.join(', ')}`);
    }
    if (type === 'security.finding') {
      await this.recordFinding(token, payload);
      return;
    }
    await eventQueries(this.db).create({
      id: generateEventId(),
      project_id: token.project_id,
      type,
      source: 'system',
      env_name: null,
      ref_sha: null,
      ref_branch: null,
      actor_type: 'system',
      actor_id: null,
      payload_json: { ...(payload && typeof payload === 'object' ? payload as Record<string, unknown> : {}),
        job_id: token.job_id, attempt_id: token.attempt_id },
      dedupe_key: `resource:${token.attempt_id}:${type}`,
    } as never);
  }

  /**
   * A finding for a rule the runner applies itself, with the profile the
   * worker decided (a runner has no database). Recorded under the job's
   * project, as the job.
   */
  private async recordFinding(token: JobTokenPayload, payload: unknown): Promise<void> {
    const { rule, detail } = (payload ?? {}) as { rule?: unknown; detail?: unknown };
    if (typeof rule !== 'string' || !RUNNER_FINDING_RULES.includes(rule)) {
      throw new BadRequestException(`A runner records findings only for ${RUNNER_FINDING_RULES.join(', ')}`);
    }
    const flat: Record<string, string | number | boolean | null> = {};
    for (const [k, v] of Object.entries(detail && typeof detail === 'object' ? detail as Record<string, unknown> : {}).slice(0, 20)) {
      if (v === null || typeof v === 'number' || typeof v === 'boolean') flat[k] = v;
      else if (typeof v === 'string') flat[k] = v.slice(0, 500);
    }
    await this.security.decide(rule, {
      projectId: token.project_id,
      governing: 'project',
      actor: { user_id: token.user_id, is_job_token: true, job_id: token.job_id } as AuthUser,
      detail: { ...flat, job_id: token.job_id, attempt_id: token.attempt_id ?? null },
    });
  }

  async updateRuntimeMeta(attemptId: string, meta: unknown): Promise<void> {
    if (!meta || typeof meta !== 'object' || Array.isArray(meta)) throw new BadRequestException('meta must be an object');
    const extra = Object.keys(meta).filter((key) => !(RUNNER_RUNTIME_META_KEYS as readonly string[]).includes(key));
    if (extra.length > 0) {
      throw new BadRequestException(`A runner reports only ${RUNNER_RUNTIME_META_KEYS.join(', ')} (got ${extra.join(', ')})`);
    }
    const { self_check: selfCheck, ...update } = meta as Record<string, unknown>;
    // The egress self-check is reported once, before job code runs; job code holds the same token.
    if (selfCheck !== undefined && !await this.jobs.setRuntimeMetaOnce(attemptId, 'self_check', selfCheck)) {
      throw new ConflictException('This attempt has already reported its self-check');
    }
    if (Object.keys(update).length === 0) return;
    // Keep the toolchain image IDs the worker recorded at pod start.
    if (update.toolchains && typeof update.toolchains === 'object') {
      const [attempt] = await this.db<{ runtime_meta: { toolchains?: { image_ids?: unknown } } | null }[]>`
        SELECT runtime_meta FROM job_attempts WHERE id = ${attemptId}::uuid
      `;
      const imageIds = attempt?.runtime_meta?.toolchains?.image_ids;
      if (imageIds) update.toolchains = { ...(update.toolchains as Record<string, unknown>), image_ids: imageIds };
    }
    await this.jobs.updateRuntimeMeta(attemptId, update);
  }

  /**
   * A message on the job's own chat thread or its parent's coordination
   * thread. It is posted as the job's own agent (its assignee, else the job):
   * the actor the body names is ignored, since job code holds the same token.
   */
  async createThreadMessage(token: JobTokenPayload, body: Record<string, unknown>): Promise<void> {
    const threadId = body.thread_id;
    const text = body.body;
    if (typeof threadId !== 'string' || typeof text !== 'string' || !text || text.length > MAX_THREAD_MESSAGE) {
      throw new BadRequestException('thread_id and a body of at most 16 KiB are required');
    }
    const job = await this.jobs.findById(token.job_id) as { assignee?: string | null } | null;
    const agentId = job?.assignee || token.job_id;
    if (body.chat_progress === true) {
      await this.deliverChatProgress(token, threadId, text, agentId);
      return;
    }
    if (!(await this.jobThreads(token.job_id)).has(threadId)) {
      throw new ForbiddenException("A runner posts only to its job's own chat or coordination thread");
    }
    await threadMessageQueries(this.db).create({
      id: typeof body.id === 'string' && body.id ? body.id : randomUUID(),
      thread_id: threadId,
      direction: 'outbound',
      actor_type: 'agent',
      actor_id: agentId,
      body: text,
      job_id: token.job_id,
    } as never);
  }

  /**
   * eve-message progress from a chat job's runner, delivered to its chat
   * thread and provider exactly as the inline path's internal chat delivery
   * route does. Only the job's own chat thread, and within the relay's
   * limits, since job code holds the same token.
   */
  private async deliverChatProgress(token: JobTokenPayload, threadId: string, text: string, agentId?: string): Promise<void> {
    if (!this.chat) throw new HttpException('Chat delivery is not available', HttpStatus.SERVICE_UNAVAILABLE);
    const threads = threadQueries(this.db);
    const reader = { findThreadProjectId: async (id: string) => (await threads.findById(id))?.project_id ?? null };
    const job = await this.jobs.findById(token.job_id) as { labels?: string[] | null; hints?: Record<string, unknown> | null; project_id: string } | null;
    const chatThread = await projectThreadId(reader, chatThreadIdOf(job), job?.project_id);
    if (!chatThread || chatThread !== threadId) {
      throw new ForbiddenException("Chat progress goes only to a chat job's own chat thread");
    }
    const [sent] = await this.db<{ count: number; last: Date | null }[]>`
      SELECT COUNT(*)::int AS count, MAX(created_at) AS last FROM thread_messages
      WHERE job_id = ${token.job_id} AND kind = 'progress'
    `;
    if ((sent?.count ?? 0) >= EVE_MESSAGE_CHAT_MAX_PER_JOB
      || (sent?.last && Date.now() - new Date(sent.last).getTime() < EVE_MESSAGE_CHAT_RATE_LIMIT_MS)) {
      throw new HttpException('Chat progress limit reached for this job', HttpStatus.TOO_MANY_REQUESTS);
    }
    await this.chat.deliverChatResult({
      projectId: token.project_id,
      job_id: token.job_id,
      thread_id: threadId,
      text: text.length > 503 ? `${text.slice(0, 500)}...` : text,
      agent_id: agentId,
      progress: true,
    });
  }

  private async jobThreads(jobId: string): Promise<Set<string>> {
    const threads = threadQueries(this.db);
    const reader = { findThreadProjectId: async (id: string) => (await threads.findById(id))?.project_id ?? null };
    const job = await this.jobs.findById(jobId);
    const allowed = new Set<string>();
    if (!job) return allowed;
    const own = await projectThreadId(reader, (job.hints as { thread_id?: unknown } | null)?.thread_id, job.project_id);
    if (own) allowed.add(own);
    if (job.parent_id) {
      const parent = await this.jobs.findById(job.parent_id);
      const coordination = (parent?.hints as { coordination?: { thread_id?: unknown } } | null)?.coordination;
      const coord = await projectThreadId(reader, coordination?.thread_id, parent?.project_id);
      if (coord) allowed.add(coord);
    }
    return allowed;
  }

  async recordResult(attemptId: string, result: RunnerResultReport): Promise<void> {
    if (!result || typeof result.success !== 'boolean' || typeof result.exit_code !== 'number') {
      throw new BadRequestException('A result needs success and exit_code');
    }
    if (!await runnerResultQueries(this.db).record(attemptId, result as unknown as Record<string, unknown>)) {
      throw new ConflictException(`Attempt ${attemptId} already has a result`);
    }
  }

  /**
   * A refreshed Codex auth.json from the job. Accepted only when the account
   * claim of its issuer-signed id_token, that of its access token when the
   * access token is a JWT (verified when it names the issuer and a published
   * key, else decoded; unexpired), and its plain account_id when present, all
   * name the stored credential's account, and it carries the stored
   * credential's API key (or none, as the stored one does). An access token
   * that is not a JWT is not checked, and that is logged. It goes to the
   * secret's own scope, or, under the project's strict
   * secrets.job_org_write, to project scope only.
   *
   * Accepted residual: the refresh token is opaque and cannot be checked, so
   * a job can write back a refresh token of its choosing beside the stored
   * account's id_token; the next refresh then follows it. Under `audit` that
   * reaches every job sharing an org-scope credential. Under `strict`,
   * secrets.job_org_write sends an org-scope write-back to the job's own
   * project (mayJobWriteSecret refuses org scope for a job token), so it
   * reaches only that project. A project- or user-scope credential is
   * written in place on every profile.
   */
  async writeBackCredential(token: JobTokenPayload, key: unknown, value: unknown): Promise<void> {
    if (typeof key !== 'string' || !(RUNNER_WRITABLE_CREDENTIALS as readonly string[]).includes(key)) {
      throw new BadRequestException(`A runner writes back only ${RUNNER_WRITABLE_CREDENTIALS.join(', ')}`);
    }
    if (typeof value !== 'string' || !value) throw new BadRequestException('value is required');

    const job = await this.jobs.findById(token.job_id);
    const harness = (job as { harness?: string | null } | null)?.harness ?? 'codex';
    const stored = (await this.secrets.resolveForJob(token.project_id, token.job_id, harness))
      .find((secret) => secret.key === key && !secret.clone_only);
    if (!stored?.scope_type || !stored.scope_id) throw new NotFoundException(`The job holds no ${key}`);
    if (stored.scope_type === 'system') throw new ForbiddenException('A job cannot write a system secret');

    const decode = (b64: string) => Buffer.from(b64, 'base64').toString('utf8');
    const storedAccount = codexAccountIdOf(decode(stored.value));
    let account: string;
    try {
      account = await verifiedCodexAccountId(decode(value), await this.codexJwks(), Date.now(), (message) =>
        this.logger.log(`Codex write-back for job ${token.job_id}: ${message}`));
    } catch (error) {
      this.logger.warn(`Refused Codex write-back for job ${token.job_id}: ${error instanceof Error ? error.message : String(error)}`);
      throw new ConflictException('The refreshed credential does not carry a verifiable account');
    }
    if (!storedAccount || storedAccount !== account) {
      this.logger.warn(`Refused Codex write-back for job ${token.job_id}: its account differs from the stored credential's`);
      throw new ConflictException('The refreshed credential belongs to another account');
    }
    // A refresh never changes the API key the file carries.
    if (codexApiKeyOf(decode(value)) !== codexApiKeyOf(decode(stored.value))) {
      this.logger.warn(`Refused Codex write-back for job ${token.job_id}: it changes the stored credential's API key`);
      throw new ConflictException('The refreshed credential changes its API key');
    }

    // Rule secrets.job_org_write: an org-scope write-back only outside the
    // project's strict profile (recorded under audit); under strict the
    // refreshed credential goes to the job's own project instead.
    const caller = { user_id: token.user_id, is_job_token: true, job_id: token.job_id, attempt_id: token.attempt_id,
      project_id: token.project_id, org_id: token.org_id ?? undefined } as AuthUser;
    if (!await this.secrets.mayJobWriteSecret(caller, stored.scope_type, key)) {
      await this.secrets.create('project', token.project_id, { key, value, type: stored.type });
      return;
    }
    if (!await this.secrets.updateIfExists(stored.scope_type, stored.scope_id, key, value)) {
      throw new NotFoundException(`Secret ${key} not found`);
    }
  }
}
