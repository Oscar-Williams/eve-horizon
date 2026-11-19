import { watchJobCancellation, bindProcessCancellation, cleanupAttemptWorkspace, JOB_CANCELLED, type JobCancellationMonitor } from '@eve/shared';
import { Injectable, Inject, type OnModuleInit } from '@nestjs/common';
import { execFile } from 'child_process';
import * as readline from 'readline';
import { promisify } from 'util';
import { createHash } from 'crypto';
import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { createStorageClient, type ObjectStorageClient } from '@eve/shared';
import {
  type HarnessInvocation,
  type HarnessResult,
  type SecretResolveItem,
  isAuthErrorMessage,
  type LifecycleEvent,
  type LifecyclePhase,
  type LifecycleAction,
  getCorrelationLogFields,
  lifecycleLogType,
  type JobGit,
  type ResolvedGitMetadata,
  buildSecurityPolicyPreamble,
  buildSecurityClaudeMd,
  loadConfigWithoutDatabase,
  DEFAULT_BILLING_DEFAULTS_V1,
  DEFAULT_RATE_CARD_EFFECTIVE_AT,
  DEFAULT_RATE_CARD_NAME,
  DEFAULT_RATE_CARD_V1,
  DEFAULT_RATE_CARD_VERSION,
  DEFAULT_RESOURCE_CLASS_NAME,
  DEFAULT_RESOURCE_CLASSES_V1,
  calculateBilledCost,
  parseResourceClassesV1,
  resolveResourceClassName,
  getResourceClassSpec,
  parseBillingDefaultsV1,
  resolveBillingConfigV1,
  type RateCardV1,
  parseResourceUri,
  defaultMountPathForUri,
  isValidMountPath,
  handleCommitPolicy,
  handlePushPolicy,
  sanitizeFilename,
  type ChatFile,
  type AttachmentIndex,
  selectClaudeAuth,
  scrubClaudeAuthEnv,
  prepareClaudeRuntimeConfig,
  materializeClaudeCredentials,
  redactAuthDecision,
  readClaudeApiKeySource,
  detectClaudeAuthFailure,
  type ClaudeAuthDecision,
  type ClaudeRuntimeConfig,
  type ClaudeCredentialMaterialization,
  ensureToolchains,
  ToolchainProvisionError,
  probeBrowserRuntime,
  rejectBrowserPathOverrides,
  mayReadJobAttachment,
  DEFAULT_AGENT_PERMISSIONS,
  RunnerApiClient,
  RUNNER_DECIDED_RULES,
  RUNNER_SETTINGS,
  selectRunnerClass,
  type SecurityProfile,
  type PreparedAgentJob,
  type RunnerContextFile,
  type RunnerResource,
  type RunnerSubmit,
} from '@eve/shared';
// Shared invoke module — single source of truth for agent-execution logic
import {
  runGit,
  getLocalRepoPath,
  redactRepoUrl,
  readPositiveInt,
  readMaxCostHint,
  extractResults,
  type ExtractedResult,
  calculateBudgetTokenBreakdown,
  EveMessageRelay,
  deliverProvisioningError,
  writeCoordinationInbox,
  writeThreadContext,
  writeCarryoverContext,
  cleanupWorkspaceSecretArtifacts,
  prepareGitAuth,
  materializeSecrets,
  releaseCloneOnlyGitKey,
  assertCloneOnlyGitCredentialSafe,
  writeBackCodexAuth,
  preexistingCodexAuthPaths,
  removeStaleServiceHomeCodexAuth,
  writeJobCodexAuth,
  operatorCodexAuth,
  mayUseRuntimeCodexAuth,
  selectJobSecrets,
  applyEnvOverrides,
  materializeWorkspaceSkills,
  runAcquireHooks,
  runReleaseHook,
  emitResourceHydrationEvent,
  getInvocationJobToken,
  resolveInvocationJobToken,
  type CoordinationDb,
  type CarryoverContextDb,
  type RelayDb,
  type LifecycleLogger,
  type BudgetState,
} from '@eve/shared';
import {
  type Db,
  agentQueries,
  executionLogQueries,
  jobQueries,
  orgQueries,
  orgDocumentQueries,
  jobAttachmentQueries,
  eventQueries,
  exchangeRateQueries,
  pricingRateCardQueries,
  projectManifestQueries,
  projectQueries,
  systemSettingsQueries,
  threadMessageQueries,
  runnerResultQueries,
  runnerModeFor,
  recordRunnerModeFinding,
  decideSecurityRule,
  governingSecurityProfile,
  type RunnerModeDecision,
} from '@eve/db';
import { inKubernetes, runnerSelfCheckMode, strictNeedsRunnerPods } from '../execution/runner-mode.js';
import { resolveHarnessAdapter, type HarnessName, type PermissionPolicy, type HarnessHelpers } from '@eve/shared';
import { CHECKOUT_SETTINGS_RULE, holdCheckoutSettings } from '@eve/shared';
import { selectedCodexAuth, type CodexAuthSelection } from '@eve/shared';
import { dispatchToRunnerPod, runnerApiUrl, type RunnerOutcome } from './runner-dispatch.js';
import { orgFsPodMount } from './org-fs-plan.js';
import { buildSanitizedHarnessEnv, buildAppApiEnvVars, mintJobAppLinkTokens } from '@eve/shared';
import { GitWorkspace, type GitAuth as GitWorkspaceAuth } from '@eve/shared';
import { resolveProjectSecrets, mintJobToken, updateSecret } from '@eve/shared';
import { extractPrefixedEnv, writeEveCredentials } from '@eve/shared';
import { createJobUserHome, cleanupJobSecretArtifacts, buildEveAgentCliArgs, spawnHarnessProcess } from '@eve/shared';
import { materializeScopedOrgFsMount, type OrgFsMountSpec } from '@eve/shared';
import { internalAuthHeaders, serviceHelperEnv } from '@eve/shared';

const execFileAsync = promisify(execFile);

interface OAuthTokens {
  accessToken: string;
  expiresAt?: number;
}

type ClaudeAuthRuntimeState = {
  runtimeConfig: ClaudeRuntimeConfig;
  materialized: ClaudeCredentialMaterialization;
};

type ServiceProvisioning = {
  env: Record<string, string>;
  cleanup: () => Promise<void>;
};

type GitAuth = {
  cloneUrl?: string;
  env?: NodeJS.ProcessEnv;
};

@Injectable()
export class InvokeService implements OnModuleInit {
  private logs: ReturnType<typeof executionLogQueries>;
  private jobs: ReturnType<typeof jobQueries>;
  private orgs: ReturnType<typeof orgQueries>;
  private projects: ReturnType<typeof projectQueries>;
  private documents: ReturnType<typeof orgDocumentQueries>;
  private attachments: ReturnType<typeof jobAttachmentQueries>;
  private events: ReturnType<typeof eventQueries>;
  private _storageClient: ObjectStorageClient | null = null;
  /**
   * Set in a runner pod: the job the worker prepared and the attempt's push
   * routes. The runner has no database: reads come from `prepared`, writes go
   * through `client`.
   */
  private runner: {
    prepared: PreparedAgentJob;
    client: RunnerApiClient;
    logs: Array<{ type: string; content: Record<string, unknown> }>;
    gitMeta?: ResolvedGitMetadata;
  } | null = null;

  /**
   * The service as a runner pod runs it: no database, the prepared job, and
   * the attempt's push-only routes for everything it writes.
   */
  static forRunner(prepared: PreparedAgentJob, client: RunnerApiClient, sink: { appendLog(type: string, content: Record<string, unknown>): void }): InvokeService {
    const service = new InvokeService(null as unknown as Db);
    const runner = { prepared, client, logs: [] as Array<{ type: string; content: Record<string, unknown> }> } as NonNullable<InvokeService['runner']>;
    service.runner = runner;
    const own = prepared.invocation;
    const unavailable = (what: string) => async () => { throw new Error(`${what} is not available in a runner pod`); };
    service.logs = {
      appendLog: async (_attemptId: string, type: string, content: Record<string, unknown>) => {
        runner.logs.push({ type, content });
        sink.appendLog(type, content);
      },
      listLogs: async () => runner.logs.map((entry, i) => ({ seq: i + 1, type: entry.type, content: entry.content })),
    } as never;
    service.jobs = {
      findById: async (id: string) => (id === own.jobId
        ? { id, project_id: own.projectId, phase: 'active', actor_user_id: prepared.actor_user_id ?? null, hints: prepared.relay?.jobs[id]?.hints ?? {} }
        : null),
      updateRuntimeMeta: async (_attemptId: string, meta: Record<string, unknown>) => { await client.updateRuntimeMeta(meta); return null; },
      markExecutionStarted: async () => undefined,
    } as never;
    service.events = { create: async (event: { type: string; payload_json?: Record<string, unknown> }) => {
      await client.emitEvent(event.type, event.payload_json ?? {});
      return event;
    } } as never;
    service.projects = { findById: unavailable('project lookup') } as never;
    service.orgs = { findById: unavailable('org lookup') } as never;
    service.documents = { findByOrgAndPath: unavailable('org document lookup') } as never;
    service.attachments = { findByJobIdAndName: unavailable('attachment lookup') } as never;
    return service;
  }

  /** Git metadata the runner recorded for its attempt (sent with its result). */
  runnerGitMeta(): ResolvedGitMetadata | undefined {
    return this.runner?.gitMeta;
  }

  /** Earlier versions wrote jobs' Codex auth into this service's HOME; remove what is left (k8s only). */
  async onModuleInit(): Promise<void> {
    await removeStaleServiceHomeCodexAuth();
  }

  constructor(@Inject('DB') private db: Db) {
    this.logs = executionLogQueries(this.db);
    this.jobs = jobQueries(this.db);
    this.orgs = orgQueries(this.db);
    this.projects = projectQueries(this.db);
    this.documents = orgDocumentQueries(this.db);
    this.attachments = jobAttachmentQueries(this.db);
    this.events = eventQueries(this.db);
  }

  private async logClaudeAuthSelected(
    invocation: HarnessInvocation,
    harness: HarnessName,
    decision: ClaudeAuthDecision | null,
    runtime: ClaudeAuthRuntimeState | null,
    scrubbedKeys: string[],
    jobUserHome: string,
    baseUrlSet: boolean,
  ): Promise<void> {
    const redacted = redactAuthDecision(decision);
    const warnings = [
      ...(redacted.warnings ?? []),
      ...(runtime?.materialized.warning ? [runtime.materialized.warning] : []),
    ];
    const payload = {
      event: 'claude_auth_selected',
      harness,
      ...redacted,
      warnings: warnings.length > 0 ? warnings : undefined,
      runtime_config_dir: runtime?.runtimeConfig.configDir ?? null,
      source_config_dir: runtime?.runtimeConfig.sourceConfigDir ?? null,
      credentials_path: runtime?.materialized.written ? runtime.materialized.path : null,
      credentials_materialized: Boolean(runtime?.materialized.written),
      scrubbed_keys: scrubbedKeys,
      home: jobUserHome,
      base_url_set: baseUrlSet,
    };

    await this.logs.appendLog(invocation.attemptId, 'claude_auth_selected', payload);
    await this.logLifecycleEvent(invocation.attemptId, 'secrets', 'log', {
      kind: 'claude_auth_selected',
      ...payload,
    });
  }

  private async logCodexAuthSelected(
    invocation: HarnessInvocation,
    harness: HarnessName,
    selection: CodexAuthSelection,
  ): Promise<void> {
    const payload = {
      event: 'codex_auth_selected',
      harness,
      ...selection,
    };

    await this.logs.appendLog(invocation.attemptId, 'codex_auth_selected', payload);
    await this.logLifecycleEvent(invocation.attemptId, 'secrets', 'log', {
      kind: 'codex_auth_selected',
      ...payload,
    });
  }

  private async emitClaudeAuthFailed(
    invocation: HarnessInvocation,
    decision: ClaudeAuthDecision | null,
    failure: { reason: string; apiKeySource?: string },
    apiKeySource: string | null,
  ): Promise<string> {
    const effectiveApiKeySource = failure.apiKeySource ?? apiKeySource ?? 'unknown';
    const probableCause = this.classifyClaudeAuthFailureCause(decision, effectiveApiKeySource);
    const hint = `Run: eve auth verify --harness claude --project ${invocation.projectId} --json`;
    const message =
      `Claude Code rejected the selected credential (apiKeySource=${effectiveApiKeySource}). ` +
      `${probableCause} ${hint}`;
    const payload = {
      event: 'claude_auth_failed',
      ...redactAuthDecision(decision),
      apiKeySource: effectiveApiKeySource,
      reason: failure.reason,
      probable_cause: probableCause,
      hint,
    };

    await this.logs.appendLog(invocation.attemptId, 'claude_auth_failed', payload);
    await this.logLifecycleEvent(invocation.attemptId, 'secrets', 'log', {
      kind: 'claude_auth_failed',
      ...payload,
    });
    await deliverProvisioningError(this.buildRelayDb(), {
      jobId: invocation.jobId,
      parentJobId: invocation.parentJobId ?? null,
      assignee: invocation.agentId ?? null,
      errorCode: 'claude_auth_failed',
      message,
    });

    return message;
  }

  private classifyClaudeAuthFailureCause(
    decision: ClaudeAuthDecision | null,
    apiKeySource: string,
  ): string {
    if (!decision) {
      return 'No Claude credential was selected; set CLAUDE_CODE_OAUTH_TOKEN or ANTHROPIC_API_KEY on the project or org.';
    }
    if (apiKeySource === 'none') {
      return 'The selected credential was not honored by Claude Code; check CLAUDE_CONFIG_DIR materialization and env propagation.';
    }
    if (decision.tokenClass === 'setup-token') {
      return 'The selected setup-token is invalid or revoked.';
    }
    if (decision.tokenClass === 'oauth') {
      return 'The selected short-lived OAuth token is expired or invalid.';
    }
    return 'The selected API key was rejected; check key validity and whether a more-specific setup-token should override it.';
  }

  private async resolveClaudeAuthDecision(
    resolvedSecrets: SecretResolveItem[],
    env: Record<string, string | undefined>,
    invocation?: Pick<HarnessInvocation, 'secrets_allowlist' | 'credentials_from_secrets_only'>,
  ): Promise<ClaudeAuthDecision | null> {
    const selected = selectClaudeAuth(resolvedSecrets);
    if (selected) return selected;
    // Under the project's strict profile only the job's own secrets count.
    if (invocation?.credentials_from_secrets_only) return null;

    const fallbackSecrets: SecretResolveItem[] = [];
    const apiKey = env.ANTHROPIC_API_KEY?.trim();
    if (apiKey) {
      fallbackSecrets.push({
        key: 'ANTHROPIC_API_KEY',
        value: apiKey,
        type: 'env_var',
        scope_type: undefined,
      });
    }
    const oauthToken = env.CLAUDE_CODE_OAUTH_TOKEN?.trim();
    if (oauthToken) {
      fallbackSecrets.push({
        key: 'CLAUDE_CODE_OAUTH_TOKEN',
        value: oauthToken,
        type: 'env_var',
        scope_type: undefined,
      });
    }
    // The credentials file sits in the worker's own HOME: never for a job with a
    // secrets allowlist, which uses only the credentials it names.
    if (fallbackSecrets.length === 0 && !invocation?.secrets_allowlist) {
      const fileTokens = await this.readClaudeCredentialsFile();
      if (fileTokens?.accessToken) {
        fallbackSecrets.push({
          key: 'CLAUDE_CODE_OAUTH_TOKEN',
          value: fileTokens.accessToken,
          type: 'env_var',
          scope_type: undefined,
        });
      }
    }

    return selectClaudeAuth(fallbackSecrets);
  }

  /** Lazy storage client for ingest file downloads (uses same EVE_STORAGE_* config as StorageService) */
  private getStorageClient(): ObjectStorageClient | null {
    if (this._storageClient) return this._storageClient;
    this._storageClient = createStorageClient();
    return this._storageClient;
  }

  private getOrgBucketName(orgSlug: string): string {
    const prefix = process.env.EVE_STORAGE_ORG_BUCKET_PREFIX ?? 'eve-org';
    return `${prefix}-${orgSlug}`;
  }

  // -------------------------------------------------------------------------
  // DB facade builders — construct lightweight adapters that the shared
  // invoke module can use without depending on @eve/db directly.
  // -------------------------------------------------------------------------

  private buildCoordinationDb(): CoordinationDb {
    return {
      queryJobHints: async (jobId) => {
        const rows = await this.db<{ hints: Record<string, unknown> | null; project_id: string }[]>`
          SELECT hints, project_id FROM jobs WHERE id = ${jobId}
        `;
        return rows[0];
      },
      findThreadProjectId: async (threadId) => {
        const rows = await this.db<{ project_id: string | null }[]>`
          SELECT project_id FROM threads WHERE id = ${threadId}
        `;
        return rows[0]?.project_id ?? null;
      },
      listThreadMessages: (threadId, opts) => threadMessageQueries(this.db).listByThread(threadId, opts),
      findJobById: async (jobId) => {
        const row = await this.jobs.findById(jobId);
        return row ?? undefined;
      },
    };
  }

  private buildCarryoverContextDb(): CarryoverContextDb {
    return {
      findJobById: async (jobId) => {
        const row = await this.jobs.findById(jobId);
        return row ?? undefined;
      },
      findProjectById: async (projectId) => {
        const row = await this.projects.findById(projectId);
        return row ?? undefined;
      },
      listOrgDocsByPrefix: (orgId, prefix, limit) =>
        this.documents.listByOrgAndPrefixWithContent(orgId, prefix, limit),
      findOrgDocByPath: async (orgId, docPath) => {
        const row = await this.documents.findByOrgAndPath(orgId, docPath);
        return row ?? undefined;
      },
      findJobAttachment: async (jobId, name) => {
        const row = await this.attachments.findByJobIdAndName(jobId, name);
        return row ?? undefined;
      },
      queryJobHints: async (jobId) => {
        const rows = await this.db<{ hints: Record<string, unknown> | null; project_id: string }[]>`
          SELECT hints, project_id FROM jobs WHERE id = ${jobId}
        `;
        return rows[0];
      },
      findThreadProjectId: async (threadId) => {
        const rows = await this.db<{ project_id: string | null }[]>`
          SELECT project_id FROM threads WHERE id = ${threadId}
        `;
        return rows[0]?.project_id ?? null;
      },
      listThreadMessages: (threadId, opts) => threadMessageQueries(this.db).listByThread(threadId, opts),
    };
  }

  private buildRelayDb(): RelayDb {
    if (this.runner) {
      const { relay } = this.runner.prepared;
      const client = this.runner.client;
      return {
        queryJobHints: async (jobId) => relay?.jobs[jobId] ?? undefined,
        findThreadProjectId: async (threadId) => relay?.threads[threadId] ?? null,
        createThreadMessage: async (msg) => {
          await client.createThreadMessage({ id: msg.id, thread_id: msg.thread_id, body: msg.body, actor_type: msg.actor_type, actor_id: msg.actor_id });
        },
      };
    }
    return {
      queryJobHints: async (jobId) => {
        const rows = await this.db<{ hints: Record<string, unknown> | null; project_id: string }[]>`
          SELECT hints, project_id FROM jobs WHERE id = ${jobId}
        `;
        return rows[0];
      },
      findThreadProjectId: async (threadId) => {
        const rows = await this.db<{ project_id: string | null }[]>`
          SELECT project_id FROM threads WHERE id = ${threadId}
        `;
        return rows[0]?.project_id ?? null;
      },
      createThreadMessage: async (msg) => {
        await threadMessageQueries(this.db).create(msg);
      },
    };
  }

  private buildLifecycleLogger(): LifecycleLogger {
    return (attemptId, phase, action, meta, opts) =>
      this.logLifecycleEvent(attemptId, phase, action, meta, opts);
  }

  /**
   * The agent's own access permissions (agents.yaml `access.permissions`), on
   * top of the agent defaults, as the agent runtime mints them.
   */
  private async resolveAgentPermissions(invocation: HarnessInvocation): Promise<string[] | undefined> {
    if (!invocation.agentId || !invocation.projectId) return undefined;
    const agent = await agentQueries(this.db).findByProjectAndId(invocation.projectId, invocation.agentId);
    const rawPerms = (agent?.access_json as Record<string, unknown> | undefined)?.permissions;
    if (!Array.isArray(rawPerms)) return undefined;
    const accessPerms = rawPerms.filter((p): p is string => typeof p === 'string');
    if (accessPerms.length === 0) return undefined;
    return [...new Set([...DEFAULT_AGENT_PERMISSIONS, ...accessPerms])];
  }

  private async getInvocationWithJobToken(invocation: HarnessInvocation): Promise<HarnessInvocation> {
    const token = await resolveInvocationJobToken(invocation, undefined, await this.resolveAgentPermissions(invocation));
    if (!token) return invocation;

    return {
      ...invocation,
      data: {
        ...(invocation.data ?? {}),
        __eve_job_token: token,
      },
    };
  }

  private async getInvocationWithAppClis(invocation: HarnessInvocation): Promise<HarnessInvocation> {
    if (!invocation.jobId) return invocation;
    const rows = await this.db<{ hints: Record<string, unknown> | null }[]>`
      SELECT hints FROM jobs WHERE id = ${invocation.jobId}
    `;
    const hints = rows[0]?.hints ?? {};
    const resolvedApis = hints.resolved_app_apis as Array<{ cli?: { name?: string; image?: string } }> | undefined;
    const resolvedLinks = hints.resolved_app_links as Array<{ cli?: { name?: string; image?: string } }> | undefined;
    const appClis = new Map<string, { name: string; image: string }>();
    for (const cli of invocation.appClis ?? []) {
      appClis.set(cli.name, cli);
    }
    for (const item of [...(resolvedApis ?? []), ...(resolvedLinks ?? [])]) {
      if (item.cli?.name && item.cli.image) {
        appClis.set(item.cli.name, { name: item.cli.name, image: item.cli.image });
      }
    }
    return {
      ...invocation,
      appClis: Array.from(appClis.values()),
    };
  }

  private async shouldSkipWorkspaceSkills(invocation: HarnessInvocation): Promise<boolean> {
    const data = (invocation.data ?? {}) as Record<string, unknown>;
    if (data.skip_workspace_skills === true || data.skip_skills === true) {
      return true;
    }
    if (this.runner) return this.runner.prepared.skip_workspace_skills === true;

    if (!invocation.jobId) return false;
    const rows = await this.db<{ hints: Record<string, unknown> | null }[]>`
      SELECT hints FROM jobs WHERE id = ${invocation.jobId}
    `;
    const hints = rows[0]?.hints ?? {};
    return hints.skip_workspace_skills === true || hints.skip_skills === true || hints.auth_probe === true;
  }

  /**
   * Log a lifecycle event for observability.
   * Events are stored in execution_logs with type = 'lifecycle_<phase>_<action>'.
   */
  private async logLifecycleEvent(
    attemptId: string,
    phase: LifecyclePhase,
    action: LifecycleAction,
    meta: Record<string, unknown>,
    opts?: { duration_ms?: number; success?: boolean; error?: string; [key: string]: unknown }
  ): Promise<void> {
    const event: LifecycleEvent = {
      ts: new Date().toISOString(),
      phase,
      action,
      ...opts,
      meta: {
        ...meta,
        ...getCorrelationLogFields(),
      },
    };
    try {
      await this.logs.appendLog(attemptId, lifecycleLogType(phase, action), event);
    } catch (err) {
      console.error(`Failed to log lifecycle event: ${err instanceof Error ? err.message : String(err)}`);
    }
  }


  private async provisionServices(
    invocation: HarnessInvocation,
    repoPath: string,
    baseEnv: NodeJS.ProcessEnv,
  ): Promise<ServiceProvisioning> {
    // NOTE: services.yaml functionality has been deprecated.
    // Service provisioning is now handled at the platform level.
    return { env: {}, cleanup: async () => {} };
  }

  /**
   * Update git_json metadata on a job attempt.
   *
   * Stores resolved git metadata (ref, SHA, branch, commits, push status) for auditing.
   *
   * @param attemptId - Attempt UUID
   * @param gitMeta - Resolved git metadata
   */
  private async updateAttemptGitMeta(
    attemptId: string,
    gitMeta: ResolvedGitMetadata | undefined,
  ): Promise<void> {
    if (!gitMeta) return;
    if (this.runner) {
      // Reported with the runner's result; the worker records it.
      this.runner.gitMeta = gitMeta;
      return;
    }
    try {
      await this.db`
        UPDATE job_attempts
        SET git_json = ${this.db.json(gitMeta as never)}::jsonb
        WHERE id = ${attemptId}::uuid
      `;
      console.log(`Updated git_json for attempt ${attemptId}:`, gitMeta);
    } catch (error) {
      console.error(`Failed to update git_json for attempt ${attemptId}:`, error);
    }
  }

  /**
   * Resolve git ref based on policy and available context.
   *
   * Resolution order for ref_policy=auto:
   * 1. Environment release SHA (if env_name is set)
   * 2. Manifest git_sha or branch
   * 3. Project default branch
   *
   * @param invocation - Harness invocation
   * @param gitConfig - Job git controls
   * @returns Resolved ref and source
   */
  private async resolveGitRef(
    invocation: HarnessInvocation,
    gitConfig: JobGit,
  ): Promise<{ ref: string; source: 'env_release' | 'manifest' | 'project_default' | 'explicit' }> {
    const refPolicy = gitConfig.ref_policy ?? 'auto';

    // A runner pod's ref was resolved by the worker.
    if (this.runner?.prepared.git_ref) return this.runner.prepared.git_ref;

    // Explicit ref provided
    if (gitConfig.ref) {
      return { ref: gitConfig.ref, source: 'explicit' };
    }

    // ref_policy=explicit requires git.ref
    if (refPolicy === 'explicit') {
      throw new Error('git.ref_policy=explicit requires git.ref to be provided');
    }

    // ref_policy=env requires env_name and release SHA
    if (refPolicy === 'env') {
      const envName = invocation.data?.env_name as string | undefined;
      if (!envName) {
        throw new Error('git.ref_policy=env requires env_name to be set');
      }
      const releaseSha = await this.getEnvironmentReleaseSha(invocation.projectId, envName);
      if (!releaseSha) {
        throw new Error(`No release SHA found for environment: ${envName}`);
      }
      return { ref: releaseSha, source: 'env_release' };
    }

    // ref_policy=project_default always uses project branch
    if (refPolicy === 'project_default') {
      const projectBranch = invocation.repoBranch ?? 'main';
      return { ref: projectBranch, source: 'project_default' };
    }

    // ref_policy=auto: try env_release → manifest → project_default
    const envName = invocation.data?.env_name as string | undefined;
    if (envName) {
      const releaseSha = await this.getEnvironmentReleaseSha(invocation.projectId, envName);
      if (releaseSha) {
        return { ref: releaseSha, source: 'env_release' };
      }
    }

    // Try manifest defaults
    const manifestRef = await this.getManifestGitRef(invocation.projectId);
    if (manifestRef) {
      return { ref: manifestRef, source: 'manifest' };
    }

    // Fall back to project default branch
    const projectBranch = invocation.repoBranch ?? 'main';
    return { ref: projectBranch, source: 'project_default' };
  }

  /**
   * Get the current release SHA for an environment.
   */
  private async getEnvironmentReleaseSha(
    projectId: string,
    envName: string,
  ): Promise<string | null> {
    try {
      const [result] = await this.db<{ sha: string | null }[]>`
        SELECT r.sha
        FROM releases r
        JOIN environments e ON e.id = r.env_id
        WHERE e.project_id = ${projectId}
          AND e.name = ${envName}
          AND r.status = 'deployed'
        ORDER BY r.deployed_at DESC
        LIMIT 1
      `;
      return result?.sha ?? null;
    } catch (error) {
      console.warn(`Failed to get environment release SHA: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  /**
   * Get git ref from manifest defaults.
   */
  private async getManifestGitRef(projectId: string): Promise<string | null> {
    try {
      const [result] = await this.db<{ parsed_defaults: Record<string, unknown> | null }[]>`
        SELECT parsed_defaults
        FROM project_manifests
        WHERE project_id = ${projectId}
        ORDER BY created_at DESC
        LIMIT 1
      `;
      if (!result?.parsed_defaults) return null;

      const defaults = result.parsed_defaults as { git?: { ref?: string; branch?: string } };
      return defaults.git?.ref ?? defaults.git?.branch ?? null;
    } catch (error) {
      console.warn(`Failed to get manifest git ref: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  /**
   * Handle branch creation based on policy.
   *
   * @param workspace - GitWorkspace instance
   * @param gitConfig - Job git controls
   * @param baseRef - Base ref to create branch from
   * @param refSource - How the base ref was resolved (for audit)
   */
  private async handleBranchCreation(
    workspace: GitWorkspace,
    gitConfig: JobGit,
    baseRef: string,
    refSource?: 'env_release' | 'manifest' | 'project_default' | 'explicit',
  ): Promise<void> {
    if (!gitConfig.branch) {
      return;
    }

    const createPolicy = gitConfig.create_branch ?? 'if_missing';
    await workspace.createBranch(gitConfig.branch, baseRef, createPolicy, refSource);
  }


  /**
   * Prepares the workspace for job execution using GitWorkspace.
   * Handles git controls: ref resolution, branch creation, and checkout.
   *
   * @param invocation - Harness invocation
   * @param gitAuth - Git authentication
   * @returns Object with repoPath and optional GitWorkspace for git controls
   */
  private async prepareWorkspaceWithGitControls(
    invocation: HarnessInvocation,
    gitAuth?: GitAuth,
  ): Promise<{ repoPath: string; gitWorkspace?: GitWorkspace; hadRepoPath: boolean }> {
    const startTime = Date.now();
    const { workspacePath, repoUrl, repoBranch } = invocation;
    // git controls are passed at top-level of HarnessInvocation, not under data
    const gitConfig = invocation.git as JobGit | undefined;

    await this.logLifecycleEvent(invocation.attemptId, 'workspace', 'start', {
      repo_url: redactRepoUrl(repoUrl ?? ''),
      branch: repoBranch,
      is_local: !!getLocalRepoPath(repoUrl ?? ''),
      has_git_controls: !!gitConfig,
    });

    try {
      if (!repoUrl) {
        throw new Error('repoUrl is required for job execution');
      }

      // Resolve the git ref based on policy
      const { ref: resolvedRef, source: refSource } = gitConfig
        ? await this.resolveGitRef(invocation, gitConfig)
        : { ref: repoBranch ?? 'main', source: 'project_default' as const };

      console.log(`Resolved git ref: ${resolvedRef} (source: ${refSource})`);

      const repoPath = path.join(workspacePath, 'repo');
      const hadRepoPath = await fs
        .stat(repoPath)
        .then((stats) => stats.isDirectory())
        .catch(() => false);

      // Create GitWorkspace with full configuration
      const workspace = new GitWorkspace({
        repoUrl,
        workspacePath,
        gitAuth: gitAuth as GitWorkspaceAuth | undefined,
        gitConfig,
        gitUser: {
          name: 'Eve Bot',
          email: 'eve@example.com',
        },
        defaultBranch: repoBranch ?? 'main',
      });

      // Initialize workspace (clone/copy repository)
      await workspace.init(resolvedRef);

      // If git controls specify a branch, handle branch creation
      if (gitConfig?.branch) {
        await this.handleBranchCreation(workspace, gitConfig, resolvedRef, refSource);
      } else {
        // Just checkout the resolved ref
        await workspace.checkout(resolvedRef, refSource);
      }

      await this.logLifecycleEvent(invocation.attemptId, 'workspace', 'end', {
        repo_url: redactRepoUrl(repoUrl),
        branch: gitConfig?.branch ?? repoBranch,
        resolved_ref: resolvedRef,
        ref_source: refSource,
        reused: hadRepoPath,
      }, { duration_ms: Date.now() - startTime, success: true });

      return {
        repoPath: workspace.getRepoPath(),
        gitWorkspace: workspace,
        hadRepoPath,
      };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      console.error(`Failed to prepare repository: ${errMsg}`);

      await this.logLifecycleEvent(invocation.attemptId, 'workspace', 'end', {
        repo_url: redactRepoUrl(repoUrl ?? ''),
      }, { duration_ms: Date.now() - startTime, success: false, error: errMsg });

      throw new Error(`Repo prep failed: ${errMsg}`);
    }
  }

  /**
   * Prepares the workspace for job execution.
   * - Ensures workspace directory exists
   * - Clones repository (required)
   *
   * If git controls are present (invocation.git), uses GitWorkspace
   * for advanced ref resolution, branch creation, and tracking.
   * Otherwise, uses legacy shallow clone behavior for backwards compatibility.
   */
  private async prepareWorkspace(
    invocation: HarnessInvocation,
    gitAuth?: GitAuth,
  ): Promise<{ repoPath: string; hadRepoPath: boolean }> {
    // Check if job has git controls (passed at top-level of HarnessInvocation)
    const gitConfig = invocation.git as JobGit | undefined;

    if (gitConfig) {
      // Use GitWorkspace for advanced git controls
      const { repoPath, hadRepoPath } = await this.prepareWorkspaceWithGitControls(invocation, gitAuth);
      return { repoPath, hadRepoPath };
    }

    // Legacy shallow clone behavior (backwards compatible)
    const startTime = Date.now();
    const { workspacePath, repoUrl, repoBranch } = invocation;

    await this.logLifecycleEvent(invocation.attemptId, 'workspace', 'start', {
      repo_url: redactRepoUrl(repoUrl ?? ''),
      branch: repoBranch,
      is_local: !!getLocalRepoPath(repoUrl ?? ''),
    });

    try {
      // Ensure workspace directory exists
      await fs.mkdir(workspacePath, { recursive: true });
      console.log(`Created workspace directory: ${workspacePath}`);

      if (!repoUrl) {
        throw new Error('repoUrl is required for job execution');
      }

      const repoPath = path.join(workspacePath, 'repo');
      const hadRepoPath = await fs
        .stat(repoPath)
        .then((stats) => stats.isDirectory())
        .catch(() => false);
      const localRepoPath = getLocalRepoPath(repoUrl);

      if (process.env.EVE_RUNTIME === 'k8s' && localRepoPath) {
        throw new Error('file:// repo URLs are not supported in k8s runtime');
      }

      if (localRepoPath) {
        console.log(`Copying local repository from ${localRepoPath} to ${repoPath}`);
        const stats = await fs.stat(localRepoPath);
        if (!stats.isDirectory()) {
          throw new Error('file:// path is not a directory');
        }
        await fs.cp(localRepoPath, repoPath, { recursive: true });
      } else {
        const cloneArgs = ['clone', '--depth', '1'];
        if (repoBranch) {
          cloneArgs.push('--branch', repoBranch);
        }
        const cloneUrl = gitAuth?.cloneUrl ?? repoUrl;
        cloneArgs.push('--', cloneUrl, repoPath);
        console.log(`Cloning repository from ${redactRepoUrl(cloneUrl)} to ${repoPath}`);
        await runGit(cloneArgs, { env: gitAuth?.env });
      }

      console.log(`Repository ready at ${repoPath}`);

      await this.logLifecycleEvent(invocation.attemptId, 'workspace', 'end', {
        repo_url: redactRepoUrl(repoUrl),
        branch: repoBranch,
        reused: hadRepoPath,
      }, { duration_ms: Date.now() - startTime, success: true });

      return { repoPath, hadRepoPath };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      console.error(`Failed to prepare repository: ${errMsg}`);

      await this.logLifecycleEvent(invocation.attemptId, 'workspace', 'end', {
        repo_url: redactRepoUrl(repoUrl ?? ''),
      }, { duration_ms: Date.now() - startTime, success: false, error: errMsg });

      throw new Error(`Repo prep failed: ${errMsg}`);
    }
  }

  private async resolveSecrets(
    projectId: string,
    userId?: string,
    attemptId?: string,
    job?: { jobId?: string; harness?: string },
  ): Promise<SecretResolveItem[]> {
    const startTime = Date.now();

    if (attemptId) {
      await this.logLifecycleEvent(attemptId, 'secrets', 'start', {
        project_id: projectId,
        user_id: userId,
      });
    }

    // A runner pod receives the job's bound secrets from the worker.
    const result = this.runner
      ? { resolved: true, secrets: this.runner.prepared.secrets, error: undefined }
      : await resolveProjectSecrets(projectId, { userId, jobId: job?.jobId, harness: job?.harness });

    if (attemptId) {
      if (!result.resolved) {
        console.error(`Secret resolution failed for project ${projectId}: ${result.error}`);
        await this.logLifecycleEvent(attemptId, 'secrets', 'end', {
          project_id: projectId,
        }, { duration_ms: Date.now() - startTime, success: false, error: result.error, resolved_count: 0 });
        throw new Error(`Secret resolution failed: ${result.error}`);
      } else {
        await this.logLifecycleEvent(attemptId, 'secrets', 'end', {
          project_id: projectId,
          resolved_count: result.secrets.length,
        }, { duration_ms: Date.now() - startTime, success: true });
      }
    } else if (!result.resolved) {
      console.error(`Secret resolution failed for project ${projectId}: ${result.error}`);
      throw new Error(`Secret resolution failed: ${result.error}`);
    }

    return result.secrets;
  }

  private async hydrateResources(
    invocation: HarnessInvocation,
    orgId: string,
    repoPath: string,
  ): Promise<{
    indexPath: string | null;
    summary: {
      resolved_count: number;
      missing_optional_count: number;
      failed_required_count: number;
      resources: Array<Record<string, unknown>>;
      resolved_at: string;
    };
  }> {
    // A runner pod has no database: the worker resolved its refs before the submit.
    const planned = this.runner ? (this.runner.prepared.resources ?? []) : await this.planResources(invocation, orgId);
    return this.materializeResources(planned, repoPath);
  }

  /**
   * Resolve a job's resource refs (worker side): org documents and job
   * attachments inline, ingest files as presigned URLs. A ref that cannot be
   * resolved carries its error code.
   */
  private async planResources(invocation: HarnessInvocation, orgId: string): Promise<RunnerResource[]> {
    const planned: RunnerResource[] = [];
    const usedMountPaths = new Map<string, string>();
    let readingJob: { actor_user_id: string | null } | null | undefined;

    for (const ref of invocation.resource_refs ?? []) {
      const required = ref.required !== false;
      const base = { uri: ref.uri, label: ref.label, required, ...(ref.mime_type ? { mime_type: ref.mime_type } : {}), ...(ref.metadata ? { metadata: ref.metadata as Record<string, unknown> } : {}) };
      const parsed = parseResourceUri(ref.uri);
      const mountPath = parsed ? (ref.mount_path ?? defaultMountPathForUri(parsed)) : '';
      if (!parsed || !isValidMountPath(mountPath)) {
        planned.push({ ...base, mount_path: '', error_code: 'resource_uri_invalid' });
        continue;
      }
      if (usedMountPaths.has(mountPath)) {
        planned.push({ ...base, mount_path: '', error_code: 'resource_mount_conflict' });
        continue;
      }
      usedMountPaths.set(mountPath, ref.uri);

      try {
        if (parsed.scheme === 'org_docs') {
          const doc = await this.documents.findByOrgAndPath(orgId, parsed.path);
          if (!doc) throw new Error('resource_not_found');
          let content = doc.content;
          let contentHash = doc.content_hash;
          let version = parsed.version ?? null;
          if (parsed.version) {
            const versionRow = await this.documents.findVersion(doc.id, parsed.version);
            if (!versionRow) throw new Error('resource_not_found');
            content = versionRow.content;
            contentHash = versionRow.content_hash;
            version = versionRow.version;
          } else {
            version = (await this.documents.getLatestVersionInfo(doc.id))?.version ?? null;
          }
          planned.push({ ...base, mount_path: mountPath, content_b64: Buffer.from(content).toString('base64'),
            content_hash: contentHash, version, mime_type: undefined, metadata: undefined });
          continue;
        }

        if (parsed.scheme === 'ingest') {
          const storageClient = this.getStorageClient();
          if (!storageClient) throw new Error('resource_storage_unavailable');
          const org = await this.orgs.findById(orgId);
          if (!org) throw new Error('resource_access_denied');
          // path.basename keeps a crafted file name inside the ingest prefix.
          const storageKey = `ingest/${parsed.ingestId}/${path.basename(parsed.fileName)}`;
          const url = await storageClient.getPresignedDownloadUrl(this.getOrgBucketName(org.slug), storageKey, 15 * 60);
          planned.push({ ...base, mount_path: mountPath, url });
          continue;
        }

        const job = await this.jobs.findById(parsed.jobId);
        if (!job) throw new Error('resource_not_found');
        const project = await this.projects.findById(job.project_id);
        if (!project || project.org_id !== orgId) throw new Error('resource_access_denied');
        const attachment = await this.attachments.findByJobIdAndName(parsed.jobId, parsed.name);
        if (!attachment) throw new Error('resource_not_found');
        // Take in only attachments this job's own actor created.
        readingJob ??= await this.jobs.findById(invocation.jobId);
        if (!readingJob || !mayReadJobAttachment(readingJob.actor_user_id, attachment)) {
          console.warn(`[resources] Skipping ${ref.uri} for job ${invocation.jobId}: attachment created by someone other than this job's actor`);
          throw new Error('resource_access_denied');
        }
        planned.push({ ...base, mount_path: mountPath, content_b64: Buffer.from(attachment.content).toString('base64'),
          content_hash: attachment.content_hash, mime_type: undefined, metadata: undefined });
      } catch (err) {
        planned.push({ ...base, mount_path: mountPath, error_code: err instanceof Error ? err.message : 'resource_not_found' });
      }
    }
    return planned;
  }

  /** Write resolved resources into `.eve/resources/` and record the index. */
  private async materializeResources(planned: RunnerResource[], repoPath: string): Promise<{
    indexPath: string | null;
    summary: {
      resolved_count: number;
      missing_optional_count: number;
      failed_required_count: number;
      resources: Array<Record<string, unknown>>;
      resolved_at: string;
    };
  }> {
    const resolvedAt = new Date().toISOString();
    const summary = {
      resolved_count: 0,
      missing_optional_count: 0,
      failed_required_count: 0,
      resources: [] as Array<Record<string, unknown>>,
      resolved_at: resolvedAt,
    };
    if (planned.length === 0) return { indexPath: null, summary };

    const resourcesDir = path.join(repoPath, '.eve', 'resources');
    await fs.mkdir(resourcesDir, { recursive: true });
    const missing = (item: RunnerResource, errorCode: string, indexPath?: string) => {
      summary.resources.push({ uri: item.uri, ...(indexPath ? { local_path: indexPath } : {}), label: item.label,
        required: item.required, status: 'missing', error_code: errorCode });
      if (item.required) summary.failed_required_count += 1;
      else summary.missing_optional_count += 1;
    };

    for (const item of planned) {
      if (!item.mount_path || !isValidMountPath(item.mount_path)) {
        missing(item, item.error_code ?? 'resource_uri_invalid');
        continue;
      }
      const localPath = path.join(resourcesDir, item.mount_path);
      const indexPath = path.posix.join('.eve', 'resources', item.mount_path);
      if (item.error_code) {
        missing(item, item.error_code, indexPath);
        continue;
      }
      try {
        let body: Buffer;
        let contentHash = item.content_hash;
        if (item.url) {
          const response = await fetch(item.url);
          if (!response.ok) throw new Error('resource_not_found');
          body = Buffer.from(await response.arrayBuffer());
          contentHash = createHash('sha256').update(body).digest('hex');
        } else {
          body = Buffer.from(item.content_b64 ?? '', 'base64');
        }
        await fs.mkdir(path.dirname(localPath), { recursive: true });
        await fs.writeFile(localPath, body);
        summary.resources.push({
          uri: item.uri,
          local_path: indexPath,
          content_hash: `sha256:${contentHash}`,
          ...(item.version !== undefined ? { version: item.version } : {}),
          label: item.label,
          required: item.required,
          status: 'resolved',
          ...(item.mime_type ? { mime_type: item.mime_type } : {}),
          ...(item.metadata ? { metadata: item.metadata } : {}),
        });
        summary.resolved_count += 1;
      } catch (err) {
        missing(item, err instanceof Error ? err.message : 'resource_not_found', indexPath);
      }
    }

    await fs.writeFile(path.join(resourcesDir, 'index.json'), JSON.stringify({
      resolved_at: resolvedAt,
      resources: summary.resources,
    }, null, 2));
    return { indexPath: '.eve/resources/index.json', summary };
  }

  /**
   * Stage chat file attachments from Eve storage into .eve/attachments/.
   * Files with eve-storage:// URLs are downloaded via the API presigned URL
   * endpoint and written to the workspace. An index.json manifest is created
   * so agents can discover attached files.
   */
  private async stageAttachments(
    workspacePath: string,
    files: ChatFile[],
    jobId: string,
  ): Promise<void> {
    const eveFiles = files.filter(f => f.url?.startsWith('eve-storage://'));
    if (eveFiles.length === 0) return;

    const attachmentsDir = path.join(workspacePath, '.eve', 'attachments');
    await fs.mkdir(attachmentsDir, { recursive: true });

    const index: AttachmentIndex = { files: [] };
    const usedNames = new Set<string>();

    const apiUrl = process.env.EVE_API_URL;

    if (!apiUrl) {
      console.warn('[attachments] EVE_API_URL not set, skipping attachment staging');
      return;
    }

    for (const file of eveFiles) {
      const key = file.url!.replace('eve-storage://', '');
      const safeName = sanitizeFilename(file.name || file.id || 'attachment');
      let filename = safeName;
      let suffix = 1;
      while (usedNames.has(filename)) {
        const dot = safeName.lastIndexOf('.');
        if (dot > 0) {
          filename = `${safeName.slice(0, dot)}-${suffix}${safeName.slice(dot)}`;
        } else {
          filename = `${safeName}-${suffix}`;
        }
        suffix += 1;
      }
      usedNames.add(filename);

      try {
        // Get presigned download URL from API
        const presignResp = await fetch(`${apiUrl}/internal/storage/chat-attachments/presign`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...internalAuthHeaders(),
          },
          // The API presigns only keys under this job's org.
          body: JSON.stringify({ key, operation: 'download', job_id: jobId }),
        });
        if (!presignResp.ok) {
          console.warn(`[attachments] Presign failed for ${key}: ${presignResp.status}`);
          continue;
        }
        const { url: downloadUrl } = await presignResp.json() as { url: string };

        // Download the file
        const response = await fetch(downloadUrl);
        if (!response.ok) {
          console.warn(`[attachments] Download failed for ${key}: ${response.status}`);
          continue;
        }

        const destPath = path.join(attachmentsDir, filename);
        await fs.writeFile(destPath, Buffer.from(await response.arrayBuffer()));

        index.files.push({
          id: file.id,
          name: file.name || file.id || 'attachment',
          path: `.eve/attachments/${filename}`,
          mimetype: file.mimetype,
          size: file.size,
          source_url: file.source_url,
          source_provider: file.source_provider,
          storage_key: file.storage_key,
        });
      } catch (err) {
        console.warn(`[attachments] Failed to stage ${key}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (index.files.length > 0) {
      await fs.writeFile(
        path.join(attachmentsDir, 'index.json'),
        JSON.stringify(index, null, 2),
      );
      console.log(`[attachments] Staged ${index.files.length} file(s) to .eve/attachments/`);
    }
  }

  // -------------------------------------------------------------------------
  // Runner pods: the worker prepares, the runner runs.
  // -------------------------------------------------------------------------

  /**
   * Run an agent job in a runner pod. The worker does the job's database and
   * internal-API work here (prepareAgentJob), sends the result in the submit
   * body, and records the attempt once the runner's result exists and its
   * pod has ended.
   */
  private async dispatchAgentJob(
    effectiveInvocation: HarnessInvocation,
    cancellation: JobCancellationMonitor,
    runnerResources: { requests?: { cpu?: string; memory?: string }; limits?: { cpu?: string; memory?: string } } | undefined,
    mode: RunnerModeDecision,
  ): Promise<HarnessResult> {
    const prepared = await this.prepareAgentJob(effectiveInvocation);
    const jobToken = getInvocationJobToken(prepared.invocation);
    if (!jobToken) throw new Error(`Could not mint a job token for ${effectiveInvocation.jobId}; a runner pod needs one`);
    const submit: RunnerSubmit = {
      kind: 'agent',
      job_id: effectiveInvocation.jobId,
      attempt_id: effectiveInvocation.attemptId,
      project_id: effectiveInvocation.projectId,
      job_token: jobToken,
      api_url: runnerApiUrl(),
      self_check: runnerSelfCheckMode(mode),
      agent: prepared,
    };
    const attemptId = effectiveInvocation.attemptId;
    const job = await this.jobs.findById(effectiveInvocation.jobId) as { labels?: string[] | null; hints?: Record<string, unknown> | null } | null;
    const hints = job?.hints ?? {};
    const orgFs = orgFsPodMount(effectiveInvocation.data?.orgfs_mount, { strict: mode.profile === 'strict' });
    const outcome = await dispatchToRunnerPod(submit, {
      pod: {
        toolchains: prepared.invocation.toolchains,
        appClis: prepared.invocation.appClis,
        resources: runnerResources,
        orgFs,
        jobClass: selectRunnerClass({
          labels: job?.labels,
          toolchains: prepared.invocation.toolchains,
          appClis: prepared.invocation.appClis,
          resourceOverride: Boolean(runnerResources),
          hint: typeof hints.runner_class === 'string' ? hints.runner_class : null,
        }),
        timeoutSeconds: typeof hints.timeout_seconds === 'number' ? hints.timeout_seconds : undefined,
        runtimeClass: (await systemSettingsQueries(this.db).get(RUNNER_SETTINGS.runtimeClass))?.value ?? null,
      },
      readResult: async (id) => (await runnerResultQueries(this.db).find(id))?.result as never ?? null,
      onPodCreated: async (runtimeMeta) => {
        try {
          await this.jobs.updateRuntimeMeta(attemptId, runtimeMeta);
        } catch (error) {
          console.error(`Failed to update runtime_meta for attempt ${attemptId}:`, error);
        }
        await this.logLifecycleEvent(attemptId, 'runner', 'log', { kind: 'runner_pod_created', ...runtimeMeta });
      },
      onSubmitted: () => this.jobs.markExecutionStarted(attemptId),
      signal: cancellation.signal,
    });
    await this.recordRunnerOutcome(effectiveInvocation, outcome);
    const { gitMeta: _gitMeta, resultReport: _report, ...result } = outcome;
    return result;
  }

  private async recordRunnerOutcome(invocation: HarnessInvocation, outcome: RunnerOutcome): Promise<void> {
    if (outcome.gitMeta) await this.updateAttemptGitMeta(invocation.attemptId, outcome.gitMeta);
    if (!outcome.success && outcome.error?.startsWith('toolchain_unavailable:')) {
      const requested = [...new Set(invocation.toolchains ?? [])];
      await this.jobs.updateRuntimeMeta(invocation.attemptId, {
        toolchains: { requested, resolved: [], missing: requested, source: 'unavailable',
          error_code: 'toolchain_unavailable', error: outcome.error },
      }).catch(() => undefined);
    }
  }

  /**
   * Everything an agent job's runner needs, resolved by the worker: the
   * effective invocation with its attempt-bound job token and app CLIs, the
   * job's bound secrets (the clone credential flagged clone_only), its git
   * ref, resources and chat attachments (inline or as presigned URLs), its
   * rendered `.eve/` context, app API links with their tokens, its budget
   * and the lookups its message relay makes.
   */
  async prepareAgentJob(effectiveInvocation: HarnessInvocation): Promise<PreparedAgentJob> {
    const invocation = await this.getInvocationWithAppClis(await this.getInvocationWithJobToken(effectiveInvocation));
    const resolution = await resolveProjectSecrets(invocation.projectId, {
      jobId: invocation.jobId,
      harness: invocation.harness,
      bound: true,
    });
    if (!resolution.resolved) throw new Error(`Secret resolution failed: ${resolution.error}`);
    await this.logLifecycleEvent(invocation.attemptId, 'secrets', 'log', {
      kind: 'runner_secrets_bound',
      keys: resolution.secrets.filter((secret) => !secret.clone_only).map((secret) => secret.key).sort(),
      clone_only: resolution.secrets.filter((secret) => secret.clone_only).map((secret) => secret.key),
    });

    const gitConfig = invocation.git as JobGit | undefined;
    const job = await this.jobs.findById(invocation.jobId);
    const project = await this.projects.findById(invocation.projectId);
    if (!project) throw new Error(`Project ${invocation.projectId} not found`);

    return {
      invocation,
      secrets: resolution.secrets,
      git_ref: gitConfig ? await this.resolveGitRef(invocation, gitConfig) : null,
      skip_workspace_skills: await this.shouldSkipWorkspaceSkills(invocation),
      resources: invocation.resource_refs?.length ? await this.planResources(invocation, project.org_id) : [],
      chat_attachments: await this.presignChatAttachments(invocation),
      context_files: await this.renderContextFiles(invocation),
      app_apis: await this.resolveAppApis(invocation),
      budget: await this.resolveBudgetEnforcementConfig(invocation).catch(() => null) as PreparedAgentJob['budget'],
      relay: await this.relayLookups(invocation),
      actor_user_id: (job as { actor_user_id?: string | null } | null)?.actor_user_id ?? null,
      rule_profiles: await this.ruleProfilesFor(invocation.projectId),
    };
  }

  /** The project's profile for each rule a runner applies itself (stamps honoured). */
  private async ruleProfilesFor(projectId: string): Promise<Record<string, SecurityProfile>> {
    const profiles: Record<string, SecurityProfile> = {};
    for (const rule of RUNNER_DECIDED_RULES) {
      profiles[rule] = await governingSecurityProfile(this.db, { projectId, governing: 'project', rule });
    }
    return profiles;
  }

  /**
   * A project rule's profile where the job runs. The worker reads it from the
   * database; a runner pod, which has none, uses the decision the worker
   * sent, and fails rather than skip a rule it was not sent.
   */
  private async decidedRuleProfile(projectId: string, rule: string): Promise<SecurityProfile> {
    if (!this.runner) return governingSecurityProfile(this.db, { projectId, governing: 'project', rule });
    const profile = this.runner.prepared.rule_profiles?.[rule];
    if (!profile) throw new Error(`${rule}: the worker sent no decision for this rule, so the runner does not start the harness`);
    return profile;
  }

  /**
   * Record a finding for a project rule the job applies. A runner pod sends it
   * through its attempt's events route (as `security.finding`).
   */
  private async recordRuleFinding(invocation: HarnessInvocation, rule: string, detail: Record<string, string | number | boolean | null>): Promise<void> {
    if (this.runner) {
      await this.runner.client.emitEvent('security.finding', { rule, detail: { job_id: invocation.jobId, ...detail } })
        .catch((err) => console.error(`[runner] Failed to record ${rule}: ${err instanceof Error ? err.message : String(err)}`));
      return;
    }
    await decideSecurityRule(this.db, rule, {
      projectId: invocation.projectId,
      governing: 'project',
      actorType: 'job',
      actorId: invocation.jobId,
      detail: { job_id: invocation.jobId, ...detail },
    });
  }

  /** Render the job's `.eve/` context (coordination inbox, thread history, carryover) into files. */
  private async renderContextFiles(invocation: HarnessInvocation): Promise<RunnerContextFile[]> {
    const scratch = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-context-'));
    try {
      const coordDb = this.buildCoordinationDb();
      await writeCoordinationInbox(invocation, scratch, coordDb);
      await writeThreadContext(invocation, scratch, coordDb);
      await writeCarryoverContext(invocation, scratch, this.buildCarryoverContextDb());
      const root = path.join(scratch, '.eve');
      const entries = await fs.readdir(root, { recursive: true, withFileTypes: true }).catch(() => []);
      const files: RunnerContextFile[] = [];
      for (const entry of entries) {
        if (!entry.isFile()) continue;
        const full = path.join(entry.parentPath ?? (entry as unknown as { path: string }).path, entry.name);
        files.push({ path: path.relative(scratch, full), content_b64: (await fs.readFile(full)).toString('base64') });
      }
      return files;
    } finally {
      await fs.rm(scratch, { recursive: true, force: true });
    }
  }

  /** Write the context files the worker rendered, under the repo's `.eve/` only. */
  private async writeContextFiles(repoPath: string, files: RunnerContextFile[]): Promise<void> {
    const eveRoot = path.join(repoPath, '.eve');
    for (const file of files) {
      const target = path.resolve(repoPath, file.path);
      if (!target.startsWith(`${eveRoot}${path.sep}`)) continue;
      await fs.mkdir(path.dirname(target), { recursive: true });
      await fs.writeFile(target, Buffer.from(file.content_b64, 'base64'));
    }
  }

  /** The job's app APIs and app links, with each link's token minted for this attempt. */
  private async resolveAppApis(invocation: HarnessInvocation): Promise<Array<Record<string, unknown>>> {
    const hintsRow = await this.db<{ hints: Record<string, unknown> | null }[]>`
      SELECT hints FROM jobs WHERE id = ${invocation.jobId}
    `;
    const resolvedApis = (hintsRow[0]?.hints?.resolved_app_apis ?? []) as Array<{ name: string; type?: string; base_url: string; cli?: unknown }>;
    const resolvedLinks = (hintsRow[0]?.hints?.resolved_app_links ?? []) as Parameters<typeof mintJobAppLinkTokens>[1];
    const links = await mintJobAppLinkTokens(invocation, resolvedLinks);
    return [
      ...resolvedApis.map((api) => ({ ...api, type: api.type ?? 'openapi' })),
      ...links,
    ] as Array<Record<string, unknown>>;
  }

  /** The job and parent hints, and the threads they name, that the message relay looks up. */
  private async relayLookups(invocation: HarnessInvocation): Promise<NonNullable<PreparedAgentJob['relay']>> {
    const relayDb = this.buildRelayDb();
    const jobs: NonNullable<PreparedAgentJob['relay']>['jobs'] = {};
    const threads: Record<string, string | null> = {};
    for (const id of [invocation.jobId, invocation.parentJobId].filter((v): v is string => Boolean(v))) {
      const row = await relayDb.queryJobHints(id);
      if (!row) continue;
      jobs[id] = { hints: row.hints, project_id: row.project_id ?? invocation.projectId };
      const coordination = (row.hints?.coordination as { thread_id?: unknown } | undefined)?.thread_id;
      for (const threadId of [row.hints?.thread_id, coordination]) {
        if (typeof threadId === 'string' && threadId && !(threadId in threads)) {
          threads[threadId] = (await relayDb.findThreadProjectId(threadId)) ?? null;
        }
      }
    }
    return { jobs, threads };
  }

  /** Presigned download URLs for the job's chat attachments (eve-storage:// files). */
  private async presignChatAttachments(invocation: HarnessInvocation): Promise<NonNullable<PreparedAgentJob['chat_attachments']>> {
    const files = (Array.isArray(invocation.data?.chat_files) ? invocation.data.chat_files : []) as ChatFile[];
    const apiUrl = process.env.EVE_API_URL;
    const staged: NonNullable<PreparedAgentJob['chat_attachments']> = [];
    if (!apiUrl) return staged;
    const usedNames = new Set<string>();
    for (const file of files.filter((f) => f.url?.startsWith('eve-storage://'))) {
      const key = file.url!.replace('eve-storage://', '');
      const filename = uniqueAttachmentName(sanitizeFilename(file.name || file.id || 'attachment'), usedNames);
      try {
        const presign = await fetch(`${apiUrl}/internal/storage/chat-attachments/presign`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', ...internalAuthHeaders() },
          // The API presigns only keys under this job's org.
          body: JSON.stringify({ key, operation: 'download', job_id: invocation.jobId }),
        });
        if (!presign.ok) {
          console.warn(`[attachments] Presign failed for ${key}: ${presign.status}`);
          continue;
        }
        const { url } = await presign.json() as { url: string };
        staged.push({ filename, url, index: {
          id: file.id, name: file.name || file.id || 'attachment', path: `.eve/attachments/${filename}`,
          mimetype: file.mimetype, size: file.size, source_url: file.source_url,
          source_provider: file.source_provider, storage_key: file.storage_key,
        } });
      } catch (err) {
        console.warn(`[attachments] Failed to presign ${key}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    return staged;
  }

  /** Download presigned chat attachments into `.eve/attachments/`, with their index. */
  private async writeChatAttachments(repoPath: string, staged: NonNullable<PreparedAgentJob['chat_attachments']>): Promise<void> {
    if (staged.length === 0) return;
    const dir = path.join(repoPath, '.eve', 'attachments');
    await fs.mkdir(dir, { recursive: true });
    const index: AttachmentIndex = { files: [] };
    for (const item of staged) {
      try {
        const response = await fetch(item.url);
        if (!response.ok) {
          console.warn(`[attachments] Download failed for ${item.filename}: ${response.status}`);
          continue;
        }
        await fs.writeFile(path.join(dir, path.basename(item.filename)), Buffer.from(await response.arrayBuffer()));
        index.files.push(item.index as AttachmentIndex['files'][number]);
      } catch (err) {
        console.warn(`[attachments] Failed to stage ${item.filename}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
    if (index.files.length > 0) await fs.writeFile(path.join(dir, 'index.json'), JSON.stringify(index, null, 2));
  }

  async execute(invocation: HarnessInvocation): Promise<HarnessResult> {
    const cancellation = await watchJobCancellation(async () => (await this.jobs.findById(invocation.jobId))?.phase);
    try {
      if (cancellation.signal.aborted) return { attemptId: invocation.attemptId, success: false, exitCode: 130, error: JOB_CANCELLED };
      const result = await this.executeCancellable(invocation, cancellation);
      await cancellation.check();
      return cancellation.signal.aborted
        ? { ...result, success: false, exitCode: 130, error: JOB_CANCELLED }
        : result;
    } finally {
      cancellation.stop();
      // Whatever the outcome, no secret written for this attempt outlives it.
      await cleanupJobSecretArtifacts(invocation);
    }
  }

  private async executeCancellable(invocation: HarnessInvocation, cancellation: JobCancellationMonitor): Promise<HarnessResult> {
    let inlineExecution = false;
    let executionSucceeded = false;
    try {
      // Apply manifest defaults if env_name is not set
      // This handles cases where jobs were created without explicit env targeting
      let effectiveInvocation = await this.applyManifestDefaults(invocation);

      // Managed model spec is detected early and passed through to invocation adapters.
      const modelSpec = (effectiveInvocation.harness_options as Record<string, unknown> | undefined)?.model as string | undefined;

      // Rule isolation.runner_mode (the outer worker; a runner pod has decided nothing to decide).
      const mode = this.runner ? null : await runnerModeFor(this.db, effectiveInvocation.projectId);
      if (mode && !inKubernetes()) {
        if (mode.required) {
          await recordRunnerModeFinding(this.db, { projectId: effectiveInvocation.projectId, profile: mode.profile,
            actorId: effectiveInvocation.jobId, detail: { kind: 'agent', job_id: effectiveInvocation.jobId, refused: 'no_kubernetes' } });
          throw strictNeedsRunnerPods('agent job');
        }
        if (mode.profile === 'audit') {
          await recordRunnerModeFinding(this.db, { projectId: effectiveInvocation.projectId, profile: mode.profile,
            actorId: effectiveInvocation.jobId, detail: { kind: 'agent', job_id: effectiveInvocation.jobId, target: 'worker-inline' } });
        }
      }

      if (mode && inKubernetes()) {
        const localRepoPath = effectiveInvocation.repoUrl ? getLocalRepoPath(effectiveInvocation.repoUrl) : null;
        if (localRepoPath) {
          throw new Error('file:// repo URLs are not supported in k8s runtime');
        }

        // Phase 5: Resolve resource class and apply k8s sizing (best-effort; falls back to env vars).
        let runnerResources: { requests?: { cpu?: string; memory?: string }; limits?: { cpu?: string; memory?: string } } | undefined;
        try {
          const resolved = await this.resolveResourceClassForJob(effectiveInvocation);
          const k8s = (resolved.spec as any)?.k8s as { cpu_request?: string; cpu_limit?: string; mem_request?: string; mem_limit?: string } | undefined;
          if (k8s?.cpu_request || k8s?.mem_request || k8s?.cpu_limit || k8s?.mem_limit) {
            runnerResources = {
              requests: {
                ...(k8s?.cpu_request ? { cpu: k8s.cpu_request } : {}),
                ...(k8s?.mem_request ? { memory: k8s.mem_request } : {}),
              },
              limits: {
                ...(k8s?.cpu_limit ? { cpu: k8s.cpu_limit } : {}),
                ...(k8s?.mem_limit ? { memory: k8s.mem_limit } : {}),
              },
            };
          }
        } catch (err) {
          console.warn(`[k8s] Failed to resolve resource class sizing for ${effectiveInvocation.jobId}: ${err instanceof Error ? err.message : String(err)}`);
        }

        return await this.dispatchAgentJob(effectiveInvocation, cancellation, runnerResources, mode);
      }

      inlineExecution = true;
      // Mark the start of execution (distinct from claim time).
      // In k8s runtime, the outer worker only spawns the runner pod; the runner pod
      // runs this same codepath with EVE_RUNTIME unset, so we only mark here.
      if (effectiveInvocation.attemptId) {
        await this.jobs.markExecutionStarted(effectiveInvocation.attemptId);
      }

      const userId = typeof effectiveInvocation.data?.user_id === 'string' ? effectiveInvocation.data.user_id : undefined;
      const allSecrets = await this.resolveSecrets(effectiveInvocation.projectId, userId, effectiveInvocation.attemptId, {
        jobId: effectiveInvocation.jobId,
        harness: effectiveInvocation.harness,
      });
      // The workspace clone may use a git credential the job itself does not receive.
      await assertCloneOnlyGitCredentialSafe(effectiveInvocation, allSecrets);
      const gitAuth = await prepareGitAuth(effectiveInvocation, allSecrets);
      // Everything from here on, harness included, sees only the job's own secrets.
      const resolvedSecrets = await selectJobSecrets(effectiveInvocation, allSecrets, this.buildLifecycleLogger());

      // Prepare workspace before execution
      // Check if job has git controls for advanced workspace handling
      // git controls are passed at top-level of HarnessInvocation, not under data
      const gitConfig = effectiveInvocation.git as JobGit | undefined;
      let repoPath: string;
      let gitWorkspace: GitWorkspace | undefined;

      let hadRepoPath = false;
      if (gitConfig) {
        // Use GitWorkspace for advanced git controls
        const result = await this.prepareWorkspaceWithGitControls(effectiveInvocation, gitAuth);
        repoPath = result.repoPath;
        gitWorkspace = result.gitWorkspace;
        hadRepoPath = result.hadRepoPath;
      } else {
        // Legacy shallow clone behavior (backwards compatible)
        const result = await this.prepareWorkspace(effectiveInvocation, gitAuth);
        repoPath = result.repoPath;
        hadRepoPath = result.hadRepoPath;
      }
      await cleanupWorkspaceSecretArtifacts(repoPath);
      await releaseCloneOnlyGitKey(effectiveInvocation, allSecrets);
      if (effectiveInvocation.attemptId) {
        await this.logLifecycleEvent(effectiveInvocation.attemptId, 'workspace', 'log', {
          had_repo_path: hadRepoPath,
        });
      }

      // Org filesystem materialization — mirrors agent-runtime's ensureOrgRoot()
      const orgFsMount = effectiveInvocation.data?.orgfs_mount;
      let orgRootPath: string | null = null;
      let orgFsMountSpec: OrgFsMountSpec = { mode: 'none', allow_prefixes: [], read_only_prefixes: [] };

      const orgRoot = process.env.EVE_ORG_FS_ROOT;
      if (orgRoot && orgFsMount) {
        const { mountPath, spec } = await materializeScopedOrgFsMount({
          workspacePath: repoPath,
          orgRoot,
          rawSpec: orgFsMount,
        });
        orgRootPath = mountPath;
        orgFsMountSpec = spec;
      }

      if (effectiveInvocation.attemptId) {
        await this.jobs.updateRuntimeMeta(effectiveInvocation.attemptId, {
          orgfs_mount: {
            mode: orgFsMountSpec.mode,
            allow_prefixes: orgFsMountSpec.allow_prefixes,
            read_only_prefixes: orgFsMountSpec.read_only_prefixes,
            mounted: Boolean(orgRootPath),
          },
        });
      }

      const secretsContext = await materializeSecrets(repoPath, effectiveInvocation, resolvedSecrets, orgRootPath);

      let resourceIndexPath: string | null = null;
      if (effectiveInvocation.resource_refs && effectiveInvocation.resource_refs.length > 0) {
        const project = this.runner ? { org_id: '' } : await this.projects.findById(effectiveInvocation.projectId);
        if (!project) {
          throw new Error(`Project ${effectiveInvocation.projectId} not found for resource hydration`);
        }

        await emitResourceHydrationEvent(this.events, effectiveInvocation, 'system.resource.hydration.started', {
          job_id: effectiveInvocation.jobId,
          attempt_id: effectiveInvocation.attemptId,
          resource_count: effectiveInvocation.resource_refs.length,
        });

        const hydration = await this.hydrateResources(effectiveInvocation, project.org_id, repoPath);
        resourceIndexPath = hydration.indexPath;

        if (resourceIndexPath) {
          secretsContext.env.EVE_RESOURCE_INDEX = resourceIndexPath;
        }

        await this.jobs.updateRuntimeMeta(effectiveInvocation.attemptId, {
          resource_hydration: hydration.summary,
          resource_index_path: resourceIndexPath,
        });

        if (hydration.summary.failed_required_count > 0) {
          await emitResourceHydrationEvent(this.events, effectiveInvocation, 'system.resource.hydration.failed', {
            job_id: effectiveInvocation.jobId,
            attempt_id: effectiveInvocation.attemptId,
            ...hydration.summary,
          });
          throw new Error('Resource hydration failed: required resources missing');
        }

        await emitResourceHydrationEvent(this.events, effectiveInvocation, 'system.resource.hydration.completed', {
          job_id: effectiveInvocation.jobId,
          attempt_id: effectiveInvocation.attemptId,
          ...hydration.summary,
        });
      }

      // Stage chat file attachments into .eve/attachments/
      const chatFiles = effectiveInvocation.data?.chat_files;
      if (this.runner) {
        await this.writeChatAttachments(repoPath, this.runner.prepared.chat_attachments ?? []);
      } else if (Array.isArray(chatFiles) && chatFiles.length > 0) {
        await this.stageAttachments(repoPath, chatFiles as ChatFile[], effectiveInvocation.jobId);
      }

      const skipWorkspaceSkills = await this.shouldSkipWorkspaceSkills(effectiveInvocation);
      if (skipWorkspaceSkills) {
        await this.logLifecycleEvent(effectiveInvocation.attemptId, 'workspace', 'log', {
          kind: 'skills_materialize_skipped',
          reason: 'auth_probe',
        });
      } else {
        await materializeWorkspaceSkills(repoPath, {
          skillMode: typeof effectiveInvocation.data?.skill_mode === 'string'
            ? effectiveInvocation.data.skill_mode
            : 'runtime',
        });
      }

      // Run workspace hooks (on-clone/on-reuse + on-acquire)
      await runAcquireHooks(
        repoPath,
        secretsContext.env,
        secretsContext.secretsFilePath,
        !hadRepoPath,
        this.buildLifecycleLogger(),
        effectiveInvocation.attemptId,
      );

      const serviceProvisioning = await this.provisionServices(effectiveInvocation, repoPath, {
        ...secretsContext.env,
      });

      try {
        const harness = (effectiveInvocation.harness ?? 'mclaude') as HarnessName;
        const permission = (effectiveInvocation.permission ?? 'yolo') as PermissionPolicy;
        const adapter = resolveHarnessAdapter(harness);
        if (!adapter) {
          throw new Error(`Unknown harness: ${harness}`);
        }
        const harnessOptions =
          (effectiveInvocation.harness_options &&
            typeof effectiveInvocation.harness_options === 'object')
            ? effectiveInvocation.harness_options
            : {};
        const invocationWithOptions = {
          ...effectiveInvocation,
          variant: effectiveInvocation.variant ?? (harnessOptions as { variant?: string }).variant,
        };

        // Log resolved secrets for debugging (keys only, not values)
        console.log(`[secrets] Resolved ${resolvedSecrets.length} secrets: [${resolvedSecrets.map(s => s.key).join(', ')}]`);

        // Capture original Codex auth for post-execution write-back comparison
        const codexAuthSecret = resolvedSecrets.find(s => s.key === 'CODEX_AUTH_JSON_B64');
        const originalCodexB64 = codexAuthSecret?.value;
        const rawCodexScopeType = codexAuthSecret?.scope_type;
        const codexScopeType = (rawCodexScopeType === 'user' || rawCodexScopeType === 'org' || rawCodexScopeType === 'project')
          ? rawCodexScopeType : undefined;
        const codexScopeId = codexAuthSecret?.scope_id;

        // Build base environment with resolved secrets for harness adapter lookup.
        // The adapter picks harness-specific vars (auth tokens, config dirs) via
        // buildOptions().  All resolved project secrets are separately forwarded
        // to the harness env so agents can use tools like `gh`, custom API keys, etc.
        const prefixedEnv = extractPrefixedEnv(['EVE_WORKER_', 'EVE_HARNESS_'], process.env);
        const baseEnv: Record<string, string | undefined> = {
          ...prefixedEnv,
          ...secretsContext.env,
          ...serviceProvisioning.env,
        };
        const isClaudeHarness = harness === 'claude' || harness === 'mclaude';
        const jobUserHome = await createJobUserHome(effectiveInvocation.attemptId);
        const claudeAuthDecision = await this.resolveClaudeAuthDecision(resolvedSecrets, baseEnv, effectiveInvocation);
        let claudeAuthRuntime: ClaudeAuthRuntimeState | null = null;

        // IMPORTANT: resolveMclaudeAuth/resolveCodeAuth must read from the per-invocation
        // env (which includes org/project/user secrets). Do not rely on worker process.env.
        const helpers: HarnessHelpers = {
          resolveMclaudeAuth: async (options) => {
            const sourceConfigDir = options?.configDir ?? path.join(os.homedir(), '.config', 'claude');
            const runtimeConfig = await prepareClaudeRuntimeConfig(
              repoPath,
              sourceConfigDir,
              jobUserHome,
              effectiveInvocation.attemptId,
              options?.harness ?? (harness === 'claude' ? 'claude' : 'mclaude'),
              options?.variant ?? invocationWithOptions.variant,
            );
            const materialized = await materializeClaudeCredentials(runtimeConfig.configDir, claudeAuthDecision);
            claudeAuthRuntime = { runtimeConfig, materialized };
            return {
              env: { ...(claudeAuthDecision?.env ?? {}) },
              configDir: runtimeConfig.configDir,
            };
          },
          resolveCodeAuth: (options?: { configDir?: string }) =>
            this.resolveCodeAuth(effectiveInvocation, harness, resolvedSecrets, { ...options, env: baseEnv, jobUserHome, repoPath }),
        };

        const options = await adapter.buildOptions({
          invocation: invocationWithOptions,
          harness,
          permission,
          repoPath,
          helpers,
          env: baseEnv,
        });

        // Build harness env: adapter-selected vars + all resolved project secrets.
        //
        // Project/org/user secrets are explicitly set by users FOR their agents.
        // They must be available in the harness process (e.g. GITHUB_TOKEN for
        // `gh`, API keys for custom integrations).
        //
        // Worker-internal vars (DATABASE_URL, EVE_SECRETS_MASTER_KEY, etc.) are
        // safely excluded by buildSanitizedHarnessEnv's allowlist — those come
        // from process.env, not from secretsContext.env.
        const harnessEnv: Record<string, string | undefined> = {
          ...secretsContext.env,
          ...(options.env ?? {}),
        };

        const envOverridesRaw = (effectiveInvocation as { env_overrides?: Record<string, string> }).env_overrides;
        rejectBrowserPathOverrides(effectiveInvocation.toolchains ?? [], envOverridesRaw);
        const envOverrideResult = await applyEnvOverrides({
          envOverrides: envOverridesRaw,
          resolvedSecrets,
          baseEnv: harnessEnv,
          strictReserved: effectiveInvocation.strict_env_overrides === true,
          onMissingSecrets: (missing) =>
            deliverProvisioningError(this.buildRelayDb(), {
              jobId: effectiveInvocation.jobId,
              parentJobId: effectiveInvocation.parentJobId ?? null,
              assignee: effectiveInvocation.agentId ?? null,
              errorCode: 'missing_secret_override',
              message: `env_overrides reference unresolved secret(s): ${missing.join(', ')}`,
            }),
        });
        Object.assign(harnessEnv, envOverrideResult.env);
        let claudeAuthFailureMessage: string | undefined;
        if (isClaudeHarness) {
          const { scrubbedKeys } = scrubClaudeAuthEnv(harnessEnv, claudeAuthDecision);
          await this.logClaudeAuthSelected(
            effectiveInvocation,
            harness,
            claudeAuthDecision,
            claudeAuthRuntime,
            scrubbedKeys,
            jobUserHome,
            Boolean(harnessEnv.ANTHROPIC_BASE_URL),
          );
        }

        const result = await this.executeEveAgentCli(
          invocationWithOptions,
          {
            ...options,
            env: harnessEnv,
          },
          repoPath,
          resourceIndexPath,
          jobUserHome,
          claudeAuthDecision,
          (message) => { claudeAuthFailureMessage = message; },
          cancellation,
        );
        if (claudeAuthFailureMessage && !result.success && !result.error?.includes(claudeAuthFailureMessage)) {
          result.error = result.error
            ? `${result.error}\n\n${claudeAuthFailureMessage}`
            : claudeAuthFailureMessage;
        }

        await cancellation.check();
        if (cancellation.signal.aborted) Object.assign(result, { success: false, exitCode: 130, error: JOB_CANCELLED });

        // Write back refreshed Codex auth.json if the token was refreshed during execution
        if (originalCodexB64 && codexScopeType && codexScopeId) {
          const runnerClient = this.runner?.client;
          await writeBackCodexAuth(originalCodexB64, codexScopeType, codexScopeId, options.env?.CODEX_HOME,
            runnerClient ? (newB64) => runnerClient.writeBackCredential('CODEX_AUTH_JSON_B64', newB64) : undefined);
        }

        if (cancellation.signal.aborted) return result;

        // Git policies: auto-commit and push after harness execution
        if (gitWorkspace && gitConfig) {
          try {
            await handleCommitPolicy(gitWorkspace, gitConfig, effectiveInvocation.jobId, result.success);
            await handlePushPolicy(gitWorkspace, gitConfig, result.success);
          } catch (gitError) {
            const msg = gitError instanceof Error ? gitError.message : String(gitError);
            console.error(`[git-policy] ${msg}`);
            result.success = false;
            result.error = result.error ? `${result.error}; ${msg}` : msg;
          }

          await this.updateAttemptGitMeta(effectiveInvocation.attemptId, gitWorkspace.getResolvedMetadata());
        }

        // Run release hook after execution (success or failure)
        await runReleaseHook(repoPath, secretsContext.env, secretsContext.secretsFilePath, this.buildLifecycleLogger(), effectiveInvocation.attemptId);

        executionSucceeded = result.success;
        return result;
      } finally {
        // The per-job HOME and secret files are removed by execute() once this returns.
        await serviceProvisioning.cleanup();
      }
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      if (error instanceof ToolchainProvisionError || errMsg.startsWith('toolchain_unavailable:')) {
        const requested = [...new Set(invocation.toolchains ?? [])];
        const toolchain = error instanceof ToolchainProvisionError ? error.toolchain : 'browser';
        const image = error instanceof ToolchainProvisionError ? error.image :
          `${process.env.EVE_TOOLCHAIN_IMAGE_PREFIX ?? 'eve-horizon/toolchain-'}${toolchain}:${process.env.EVE_TOOLCHAIN_IMAGE_TAG ?? 'local'}`;
        if (invocation.attemptId) {
          // In a runner pod the API keeps the image IDs the worker recorded.
          const [attempt] = this.runner ? [] : await this.db<{ runtime_meta: { toolchains?: { image_ids?: Record<string, string> } } }[]>`
            SELECT runtime_meta FROM job_attempts WHERE id = ${invocation.attemptId}::uuid
          `;
          await this.jobs.updateRuntimeMeta(invocation.attemptId, {
            toolchains: { requested, resolved: [], missing: requested, source: 'unavailable',
              error_code: 'toolchain_unavailable', toolchain, image, error: errMsg,
              image_ids: attempt?.runtime_meta?.toolchains?.image_ids },
          });
        }
        return { attemptId: invocation.attemptId, success: false, exitCode: 1,
          error: `toolchain_unavailable: ${toolchain} setup failed from ${image}: ${errMsg}` };
      }
      console.error(`Worker execution failed: ${errMsg}`);
      return {
        attemptId: invocation.attemptId,
        success: false,
        exitCode: 1,
        error: errMsg,
      };
    } finally {
      if (inlineExecution) await cleanupAttemptWorkspace(invocation, executionSucceeded, loadConfigWithoutDatabase());
    }
  }

  /**
   * Apply manifest defaults to invocation if env_name or other fields are not set.
   *
   * This ensures that jobs scheduled without explicit environment targeting
   * use the project's manifest defaults at execution time.
   *
   * @param invocation - Original harness invocation
   * @returns Enhanced invocation with manifest defaults applied
   */
  private async applyManifestDefaults(invocation: HarnessInvocation): Promise<HarnessInvocation> {
    // If invocation already has env_name set (or explicitly null), use it as-is.
    // A runner pod's invocation was made effective by the worker.
    const hasExplicitEnv = invocation.data?.env_name !== undefined;
    if (hasExplicitEnv || this.runner) {
      return invocation;
    }

    // Look up the latest manifest for this project
    try {
      const manifest = await this.db<{ parsed_defaults: Record<string, unknown> | null }[]>`
        SELECT parsed_defaults FROM project_manifests
        WHERE project_id = ${invocation.projectId}
        ORDER BY created_at DESC
        LIMIT 1
      `;

      if (!manifest || manifest.length === 0 || !manifest[0].parsed_defaults) {
        console.log(`No manifest defaults found for project ${invocation.projectId}, using invocation as-is`);
        return invocation;
      }

      const defaults = manifest[0].parsed_defaults as { env?: string; [key: string]: unknown };

      if (!defaults.env) {
        console.log(`Manifest for project ${invocation.projectId} has no default env, using invocation as-is`);
        return invocation;
      }

      // Apply the default environment to the invocation
      console.log(`Applying manifest default env "${defaults.env}" for job ${invocation.jobId}`);

      return {
        ...invocation,
        data: {
          ...(invocation.data ?? {}),
          env_name: defaults.env,
        },
      };
    } catch (error) {
      const errMsg = error instanceof Error ? error.message : String(error);
      console.warn(`Failed to fetch manifest defaults for project ${invocation.projectId}: ${errMsg}`);
      // Return original invocation on error - don't fail the job
      return invocation;
    }
  }

  private async getManifestDefaults(projectId: string): Promise<Record<string, unknown> | null> {
    try {
      const manifests = projectManifestQueries(this.db);
      const manifest = await manifests.findLatestByProject(projectId);
      return manifest?.parsed_defaults ?? null;
    } catch (err) {
      console.warn(`[manifest] Failed to fetch defaults for project ${projectId}: ${err instanceof Error ? err.message : String(err)}`);
      return null;
    }
  }

  private async resolveResourceClassForJob(invocation: HarnessInvocation): Promise<{ name: string | null; spec: unknown | null }> {
    const [job, manifestDefaults, setting] = await Promise.all([
      this.jobs.findById(invocation.jobId),
      this.getManifestDefaults(invocation.projectId),
      systemSettingsQueries(this.db).get('resource_classes'),
    ]);

    const resourceClasses = parseResourceClassesV1(setting?.value) ?? DEFAULT_RESOURCE_CLASSES_V1;
    const name = resolveResourceClassName({
      job_hints: (job?.hints ?? null) as Record<string, unknown> | null,
      manifest_defaults: manifestDefaults,
      fallback: DEFAULT_RESOURCE_CLASS_NAME,
    });
    const spec = getResourceClassSpec(resourceClasses, name);
    return { name, spec };
  }

  private async resolveBudgetEnforcementConfig(invocation: HarnessInvocation): Promise<{
    max_tokens: number | null;
    max_cost: { currency: string; amount: number } | null;
    pricing: {
      rate_card: { name: string; version: number; effective_at: string; rates: RateCardV1 };
      markup_pct: number;
      currency: string;
      fx_usd_to_currency: { rate: string; fetched_at: string; source: string } | null;
    };
    compute: {
      resource_class: string | null;
      requested_vcpu: number | null;
      requested_memory_gib: number | null;
      execution_started_at_ms: number;
    };
  } | null> {
    const job = await this.jobs.findById(invocation.jobId);
    if (!job) return null;

    const hints = (job.hints ?? {}) as Record<string, unknown>;
    const maxTokens = readPositiveInt(hints.max_tokens);
    const maxCost = readMaxCostHint(hints.max_cost);

    if (!maxTokens && !maxCost) {
      return null;
    }

    // Load org billing config + system defaults.
    const [orgRow] = await this.db<{ org_id: string; billing_config: Record<string, unknown> | null }[]>`
      SELECT p.org_id, o.billing_config
      FROM projects p
      JOIN orgs o ON o.id = p.org_id
      WHERE p.id = ${invocation.projectId}
      LIMIT 1
    `;

    const billingDefaultsSetting = await systemSettingsQueries(this.db).get('billing.defaults');
    let systemDefaults = DEFAULT_BILLING_DEFAULTS_V1;
    if (billingDefaultsSetting?.value) {
      try {
        systemDefaults = parseBillingDefaultsV1(billingDefaultsSetting.value);
      } catch (err) {
        console.warn(
          `[budget] Invalid system billing.defaults; falling back: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    const billing = resolveBillingConfigV1({
      system_defaults: systemDefaults,
      org_billing_config: orgRow?.billing_config,
    });
    const billingCurrency = (billing.billing_currency ?? 'usd').toLowerCase();
    const enforcementCurrency = (maxCost?.currency ?? billingCurrency).toLowerCase();

    const at = new Date();
    const rateCards = pricingRateCardQueries(this.db);
    const cardRow = await rateCards.findLatestEffective(billing.rate_card_name, at);
    const rateCard = cardRow
      ? {
          name: cardRow.name,
          version: cardRow.version,
          effective_at: cardRow.effective_at.toISOString(),
          rates: cardRow.rates_json as unknown as RateCardV1,
        }
      : {
          name: DEFAULT_RATE_CARD_NAME,
          version: DEFAULT_RATE_CARD_VERSION,
          effective_at: DEFAULT_RATE_CARD_EFFECTIVE_AT,
          rates: DEFAULT_RATE_CARD_V1,
        };

    // FX snapshot (USD -> enforcement currency).
    let fx: { rate: string; fetched_at: string; source: string } | null = null;
    if (enforcementCurrency !== 'usd') {
      const fxRow = await exchangeRateQueries(this.db).findLatest('usd', enforcementCurrency);
      if (fxRow) {
        fx = {
          rate: fxRow.rate,
          fetched_at: fxRow.fetched_at.toISOString(),
          source: fxRow.source,
        };
      }
    }

    // Compute sizing for budget include (requested resources * elapsed time).
    const resolvedClass = await this.resolveResourceClassForJob(invocation);
    const spec = resolvedClass.spec as { vcpu?: unknown; memory_gib?: unknown } | null;
    const requestedVcpu = typeof spec?.vcpu === 'number' && Number.isFinite(spec.vcpu) ? spec.vcpu : null;
    const requestedMem = typeof spec?.memory_gib === 'number' && Number.isFinite(spec.memory_gib) ? spec.memory_gib : null;

    const [attemptRow] = await this.db<{ execution_started_at: Date | null }[]>`
      SELECT execution_started_at FROM job_attempts
      WHERE id = ${invocation.attemptId}::uuid
      LIMIT 1
    `;
    const execStartedAt = attemptRow?.execution_started_at ?? new Date();

    return {
      max_tokens: maxTokens,
      max_cost: maxCost,
      pricing: {
        rate_card: rateCard,
        markup_pct: billing.markup_pct,
        currency: enforcementCurrency,
        fx_usd_to_currency: fx,
      },
      compute: {
        resource_class: resolvedClass.name,
        requested_vcpu: requestedVcpu,
        requested_memory_gib: requestedMem,
        execution_started_at_ms: execStartedAt.getTime(),
      },
    };
  }

  private async readClaudeCredentialsFile(): Promise<OAuthTokens | null> {
    const homeDir = process.env.HOME || os.homedir();
    const xdgConfigHome = process.env.XDG_CONFIG_HOME || path.join(homeDir, '.config');
    const ccConfigDir =
      process.env.CLAUDE_CONFIG_DIR ||
      path.join(homeDir, '.cc-mirror', 'mclaude', 'config');
    const candidates = [
      path.join(homeDir, '.claude', '.credentials.json'),
      path.join(homeDir, '.claude', 'credentials.json'),
      path.join(xdgConfigHome, 'claude', '.credentials.json'),
      path.join(xdgConfigHome, 'claude', 'credentials.json'),
      path.join(ccConfigDir, '.credentials.json'),
    ];

    for (const candidate of candidates) {
      try {
        const raw = await fs.readFile(candidate, 'utf-8');
        const data = JSON.parse(raw) as Record<string, unknown>;
        const oauth = data.claudeAiOauth as Record<string, unknown> | undefined;
        if (!oauth) continue;

        const accessToken = typeof oauth.accessToken === 'string' ? oauth.accessToken : undefined;
        if (!accessToken) continue;

        const expiresRaw = oauth.expiresAt;
        const expiresAt =
          typeof expiresRaw === 'number'
            ? expiresRaw
            : typeof expiresRaw === 'string' && expiresRaw.trim()
              ? Number(expiresRaw)
              : undefined;

        return {
          accessToken,
          expiresAt: Number.isFinite(expiresAt) ? expiresAt : undefined,
        };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          console.warn(`Failed to read Claude credentials file ${candidate}: ${String(error)}`);
        }
      }
    }

    return null;
  }

  /**
   * Select the Codex credential for this attempt from the per-invocation env —
   * OPENAI_API_KEY, then CODEX_AUTH_JSON_B64, then CODEX_OAUTH_ACCESS_TOKEN,
   * then pre-existing auth files — and record the redacted selection as
   * `codex_auth_selected`. `secrets` only supplies the scope of the chosen key.
   */
  private async resolveCodeAuth(
    invocation: HarnessInvocation,
    harness: HarnessName,
    secrets: SecretResolveItem[],
    options?: {
      configDir?: string;
      env?: NodeJS.ProcessEnv;
      /** The per-job HOME the harness runs with; auth files go here, never to the worker's own HOME. */
      jobUserHome?: string;
      /** The job's repo, so an auth.json in a repo-local config dir is kept out of git. */
      repoPath?: string;
    },
  ): Promise<{
    env: Record<string, string | undefined>;
  }> {
    const env = options?.env ?? process.env;
    const authTarget = { configDir: options?.configDir, jobUserHome: options?.jobUserHome, repoPath: options?.repoPath };
    const secretFor = (key: string) => secrets.find(s => s.key === key) ?? { key };

    console.log(`[codex-auth] resolveCodeAuth called: configDir=${options?.configDir ?? '(none)'} OPENAI_API_KEY=${!!env.OPENAI_API_KEY} CODEX_AUTH_JSON_B64=${!!env.CODEX_AUTH_JSON_B64} CODEX_OAUTH_ACCESS_TOKEN=${!!env.CODEX_OAUTH_ACCESS_TOKEN}`);

    // Priority 1: OPENAI_API_KEY env var
    const apiKey = env.OPENAI_API_KEY;
    if (apiKey) {
      console.log('[codex-auth] Using OPENAI_API_KEY from env');
      await this.logCodexAuthSelected(invocation, harness, selectedCodexAuth('api_key', secretFor('OPENAI_API_KEY')));
      return { env: { OPENAI_API_KEY: apiKey } };
    }

    // Priority 2: CODEX_AUTH_JSON_B64 env var (full auth.json as base64)
    // Write the complete auth.json (including refresh_token) so the Codex CLI
    // can use its native OAuth flow — reading from CODEX_HOME/auth.json and
    // auto-refreshing when the access_token expires.
    const authJsonB64 = env.CODEX_AUTH_JSON_B64;
    if (authJsonB64) {
      const authJsonStr = Buffer.from(authJsonB64, 'base64').toString('utf-8');

      try {
        const authData = JSON.parse(authJsonStr) as Record<string, unknown>;
        const tokens = authData.tokens as Record<string, unknown> | undefined;
        const hasAccessToken = typeof tokens?.access_token === 'string';
        const hasRefreshToken = typeof tokens?.refresh_token === 'string';
        const hasApiKey = typeof authData.OPENAI_API_KEY === 'string';
        console.log(
          `[codex-auth] CODEX_AUTH_JSON_B64 decoded: access_token=${hasAccessToken}, refresh_token=${hasRefreshToken}, OPENAI_API_KEY=${hasApiKey}, last_refresh=${String(authData.last_refresh ?? 'missing')}`,
        );
      } catch {
        console.warn('[codex-auth] Failed to parse CODEX_AUTH_JSON_B64 — writing raw');
      }

      // Write auth.json to CODEX_HOME and the per-job HOME (never the worker's own HOME).
      await writeJobCodexAuth(authJsonStr, authTarget);

      // Do NOT pass OPENAI_API_KEY as env var — let the Codex CLI use file-based
      // auth from CODEX_HOME/auth.json so it can auto-refresh using refresh_token.
      await this.logCodexAuthSelected(invocation, harness, selectedCodexAuth('auth_json', secretFor('CODEX_AUTH_JSON_B64')));
      return { env: {} };
    }

    // Priority 3: CODEX_OAUTH_ACCESS_TOKEN env var (access_token only, no refresh)
    const oauthToken = env.CODEX_OAUTH_ACCESS_TOKEN;
    if (oauthToken) {
      const authPayload = {
        tokens: { access_token: oauthToken },
        last_refresh: new Date().toISOString(),
      };
      const authJsonStr = JSON.stringify(authPayload, null, 2);
      await writeJobCodexAuth(authJsonStr, authTarget);
      // No refresh_token available — pass as env var fallback
      await this.logCodexAuthSelected(invocation, harness, selectedCodexAuth('oauth_access_token', secretFor('CODEX_OAUTH_ACCESS_TOKEN')));
      return { env: { OPENAI_API_KEY: oauthToken } };
    }

    // Priority 4: an auth.json already in the harness config dir (no allowlist only)
    for (const authPath of preexistingCodexAuthPaths(options?.configDir, invocation)) {
      try {
        const content = await fs.readFile(authPath, 'utf-8');
        const data = JSON.parse(content) as {
          OPENAI_API_KEY?: string;
          tokens?: { access_token?: string; refresh_token?: string };
        };
        if (data.tokens?.access_token || data.OPENAI_API_KEY) {
          console.log(`[codex-auth] Found pre-existing auth at ${authPath}`);
          await this.logCodexAuthSelected(invocation, harness, selectedCodexAuth('preexisting'));
          return { env: {} };
        }
      } catch {
        // File doesn't exist or isn't valid JSON, try next
      }
    }

    // Priority 5: operator Codex auth (the worker's own env, or a developer's
    // codex login outside k8s), for jobs without a secrets allowlist only, and
    // never under the project's strict profile.
    if (mayUseRuntimeCodexAuth(invocation)) {
      const operatorAuth = await operatorCodexAuth();
      if (operatorAuth) {
        await writeJobCodexAuth(operatorAuth, authTarget);
        await this.logCodexAuthSelected(invocation, harness, selectedCodexAuth('preexisting'));
        return { env: {} };
      }
    }

    throw new Error(
      'Missing code auth: set OPENAI_API_KEY or CODEX_AUTH_JSON_B64. Run: eve auth sync --codex',
    );
  }

  private async resolveEveAgentCliCommand(): Promise<{
    binary: string;
    prefixArgs: string[];
  }> {
    if (process.env.EVE_AGENT_CLI_PATH) {
      return { binary: process.env.EVE_AGENT_CLI_PATH, prefixArgs: [] };
    }

    const candidate = path.resolve(
      process.cwd(),
      '..',
      '..',
      'packages',
      'eve-agent-cli',
      'dist',
      'index.js',
    );

    try {
      await fs.stat(candidate);
      return { binary: process.execPath, prefixArgs: [candidate] };
    } catch {
      return { binary: 'eve-agent-cli', prefixArgs: [] };
    }
  }

  /**
   * Rule harness.checkout_settings (P2-9), under the project's profile:
   * routing settings the checkout supplies to the harness are recorded under
   * audit and strict (names only), and under strict eve-agent-cli is told to
   * keep them out; a harness with no confirmed way to is refused.
   */
  private holdCheckoutSettings(
    invocation: HarnessInvocation,
    harness: string,
    repoPath: string,
    env?: Record<string, string | undefined>,
  ): Promise<Record<string, string>> {
    // In a runner pod (no database) the worker decided the profile and the
    // finding goes through the attempt's events route.
    return holdCheckoutSettings({
      harness,
      workspace: repoPath,
      configDir: env?.CLAUDE_CONFIG_DIR ?? env?.CODEX_HOME,
      profile: () => this.decidedRuleProfile(invocation.projectId, CHECKOUT_SETTINGS_RULE),
      record: (detail) => this.recordRuleFinding(invocation, CHECKOUT_SETTINGS_RULE, detail),
    });
  }

  private async executeEveAgentCli(
    invocation: HarnessInvocation,
    options: {
      harness: string;
      permission: string;
      variant?: string;
      model?: string;
      reasoning?: string;
      env?: Record<string, string | undefined>;
    },
    repoPath: string,
    resourceIndexPath?: string | null,
    jobUserHome?: string,
    claudeAuthDecision?: ClaudeAuthDecision | null,
    onClaudeAuthFailure?: (message: string) => void,
    cancellation?: JobCancellationMonitor,
  ): Promise<HarnessResult> {
    const { binary, prefixArgs } = await this.resolveEveAgentCliCommand();
    const startTime = Date.now();
    const harnessOptions = {
      ...(options.variant ? { variant: options.variant } : {}),
      ...(options.model ? { model: options.model } : {}),
    };
    const budgetConfig = this.runner ? (this.runner.prepared.budget as Awaited<ReturnType<InvokeService['resolveBudgetEnforcementConfig']>> ?? null)
      : await this.resolveBudgetEnforcementConfig(invocation).catch((err) => {
      console.warn(
        `[budget] Failed to resolve budget config for job ${invocation.jobId}: ${err instanceof Error ? err.message : String(err)}`,
      );
      return null;
    });

    await this.logLifecycleEvent(invocation.attemptId, 'harness', 'start', {
      harness: options.harness,
      permission: options.permission,
      variant: options.variant,
      model: options.model,
      reasoning: options.reasoning,
      ...(Object.keys(harnessOptions).length > 0
        ? { harness_options: harnessOptions }
        : {}),
    });

    // Write security policy CLAUDE.md for Claude-family harnesses
    const claudeConfigDir = options.env?.CLAUDE_CONFIG_DIR;
    if (claudeConfigDir) {
      const securityMd = buildSecurityClaudeMd(repoPath);
      const claudeMdPath = path.join(claudeConfigDir, 'CLAUDE.md');
      try {
        await fs.mkdir(claudeConfigDir, { recursive: true });
        await fs.writeFile(claudeMdPath, securityMd);
      } catch (err) {
        console.warn(`Failed to write security CLAUDE.md: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (this.runner) {
      // The worker rendered the coordination inbox, thread history and carryover context.
      await this.writeContextFiles(repoPath, this.runner.prepared.context_files ?? []);
    } else {
      // Write coordination inbox if this job has a parent with a coordination thread
      const coordDb = this.buildCoordinationDb();
      await writeCoordinationInbox(invocation, repoPath, coordDb);

      // Write thread conversation history for multi-turn continuity
      await writeThreadContext(invocation, repoPath, coordDb);

      // Materialize agent context hints into .eve/context/* for carryover.
      await writeCarryoverContext(invocation, repoPath, this.buildCarryoverContextDb());
    }

    // Phase 2 secret isolation: HOME is created before harness option
    // resolution so Claude config/auth can be materialized outside repoPath.
    const effectiveJobUserHome = jobUserHome ?? await createJobUserHome(invocation.attemptId);

    // Write Eve CLI credentials so the agent can call `eve` commands
    const invocationToken = getInvocationJobToken(invocation);
    const jobToken = await writeEveCredentials(invocation, invocationToken, effectiveJobUserHome);

    const adapterEnv: Record<string, string | undefined> = {
      ...(options.env ?? {}),
      // Rule harness.checkout_settings: what eve-agent-cli needs to keep
      // checkout routing settings away from the harness under strict.
      ...await this.holdCheckoutSettings(invocation, options.harness, repoPath, options.env),
    };
    if (jobToken) {
      adapterEnv.EVE_JOB_TOKEN = jobToken;
    }

    // Inject with_apis env vars (EVE_APP_API_URL_{service}) from resolved hints
    // and set up app CLIs (chmod + add to PATH) for repo-bundled CLIs
    const appCliBinPaths: string[] = [];
    try {
      type AppApi = { name: string; type?: string; base_url: string; cli?: { name: string; bin: string; image?: string } };
      let resolvedApis: AppApi[] | undefined;
      let resolvedLinksWithTokens: Awaited<ReturnType<typeof mintJobAppLinkTokens>>;
      if (this.runner) {
        // The worker minted the link tokens; a runner pod cannot.
        const prepared = (this.runner.prepared.app_apis ?? []) as Array<AppApi & { origin?: string }>;
        resolvedApis = prepared.filter((api) => api.origin !== 'app_link');
        resolvedLinksWithTokens = prepared.filter((api) => api.origin === 'app_link') as never;
      } else {
        const hintsRow = await this.db<{ hints: Record<string, unknown> | null }[]>`
          SELECT hints FROM jobs WHERE id = ${invocation.jobId}
        `;
        resolvedApis = hintsRow[0]?.hints?.resolved_app_apis as AppApi[] | undefined;
        const resolvedLinks = hintsRow[0]?.hints?.resolved_app_links as Array<{ name: string; alias: string; subscription_id: string; type?: string; base_url: string; scopes?: string[]; producer_project_id?: string; producer_env?: string; cli?: { name: string; bin: string; image?: string } }> | undefined;
        resolvedLinksWithTokens = await mintJobAppLinkTokens(invocation, resolvedLinks ?? []);
      }
      if (resolvedApis?.length || resolvedLinksWithTokens.length > 0) {
        Object.assign(adapterEnv, buildAppApiEnvVars([
          ...(resolvedApis ?? []).map((api) => ({ ...api, type: api.type ?? 'openapi' })),
          ...resolvedLinksWithTokens,
        ]));

        // Set up repo-bundled CLIs: chmod +x and add bin dir to PATH
        for (const api of resolvedApis ?? []) {
          if (!api.cli?.bin) continue;
          const cliBinPath = path.join(repoPath, api.cli.bin);
          try {
            await fs.chmod(cliBinPath, 0o755);
            appCliBinPaths.push(path.dirname(cliBinPath));
            console.log(`[app-cli] '${api.cli.name}' available at ${cliBinPath}`);
          } catch {
            console.warn(`[app-cli] '${api.cli.name}' declared but not found: ${cliBinPath}`);
          }
        }
      }
    } catch {
      // Non-fatal — description still has the URLs
    }

      const securityPreamble = buildSecurityPolicyPreamble(repoPath);
      const fullPromptText = securityPreamble + '\n\n' + invocation.text;

      // The prompt goes to eve-agent-cli on stdin, never on its command line.
      const args = buildEveAgentCliArgs({
        harness: options.harness,
        permission: options.permission,
        workspace: repoPath,
        variant: options.variant,
        model: options.model,
        reasoning: options.reasoning,
      });

      const requestedToolchains = [...new Set(invocation.toolchains ?? [])];
      const provisionedToolchains = requestedToolchains.length > 0
        ? await ensureToolchains({ toolchains: requestedToolchains, baseEnv: serviceHelperEnv() }) : null;
      if (provisionedToolchains) Object.assign(adapterEnv, provisionedToolchains.envOverlay);
      const processEnv = buildSanitizedHarnessEnv({
        binPaths: [
          ...(provisionedToolchains?.pathPrefix.split(path.delimiter).filter(Boolean) ?? []),
          ...appCliBinPaths,
          path.resolve(process.cwd(), 'node_modules', '.bin'),
          path.resolve(process.cwd(), '..', '..', 'node_modules', '.bin'),
        ],
        jobId: invocation.jobId,
        attemptId: invocation.attemptId,
        projectId: invocation.projectId,
        repoPath,
        parentJobId: invocation.parentJobId,
        eveApiUrl: loadConfigWithoutDatabase().EVE_API_URL,
        envName: typeof invocation.data?.env_name === 'string' ? invocation.data.env_name : undefined,
        resourceIndexPath: resourceIndexPath ?? undefined,
        jobUserHome: effectiveJobUserHome,
        adapterEnv,
      });

      if (requestedToolchains.includes('browser')) {
        let probe;
        try {
          probe = await probeBrowserRuntime(processEnv, repoPath);
        } catch (error) {
          throw new ToolchainProvisionError(`Browser setup failed: ${error instanceof Error ? error.message : String(error)}`,
            'browser', `${process.env.EVE_TOOLCHAIN_IMAGE_PREFIX ?? 'eve-horizon/toolchain-'}browser:${process.env.EVE_TOOLCHAIN_IMAGE_TAG ?? 'local'}`);
        }
        await this.jobs.updateRuntimeMeta(invocation.attemptId, { browser: {
          ...probe, source_image_digest: provisionedToolchains?.sourceDigests?.browser,
          runtime_image_digest: process.env.EVE_RUNTIME_IMAGE_DIGEST ?? null,
        } });
      }

      await cancellation?.check();
      cancellation?.signal.throwIfAborted();
      return new Promise((resolve) => {
      const fullArgs = [...prefixArgs, ...args];
      console.log(`[harness] Executing: ${binary} ${fullArgs.join(' ')}`);
      console.log(`[harness-env] CODEX_HOME=${processEnv.CODEX_HOME ?? '(unset)'} OPENAI_API_KEY=${processEnv.OPENAI_API_KEY ? 'present' : '(unset)'}`);

      const harnessProcess = spawnHarnessProcess(binary, fullArgs, {
        cwd: repoPath,
        env: processEnv,
        prompt: fullPromptText,
        detached: process.platform !== 'win32',
      });
      const finishCancellation = bindProcessCancellation(harnessProcess, cancellation?.signal);

      // Budget enforcement state (Phase 7): best-effort, fail-open on internal errors.
      const llmUsageAgg = new Map<string, {
        provider: string;
        model: string;
        source: 'byok' | 'managed';
        usage: {
          input_tokens: number;
          output_tokens: number;
          cache_read_tokens: number;
          cache_write_tokens: number;
          reasoning_tokens: number;
        };
      }>();
      let budgetExceededError: string | null = null;
      let budgetKillIssued = false;
      let budgetSummaryAppended = false;
      let budgetInterval: NodeJS.Timeout | null = null;

      const formatCacheReadWeight = (weight: number | null): string =>
        weight == null ? 'full/mixed' : weight.toFixed(2);

      const estimateBudgetState = (): BudgetState | null => {
        if (!budgetConfig) return null;
        const currency = budgetConfig.pricing.currency;
        const fxRate =
          currency === 'usd'
            ? 1
            : Number(budgetConfig.pricing.fx_usd_to_currency?.rate ?? '1');

        const llmUsage = Array.from(llmUsageAgg.values()).map((e) => ({
          provider: e.provider,
          model: e.model,
          source: e.source,
          usage: e.usage,
        }));

        const nowMs = Date.now();
        const elapsedSeconds = Math.max(
          0,
          (nowMs - budgetConfig.compute.execution_started_at_ms) / 1000,
        );
        const requestedVcpu = budgetConfig.compute.requested_vcpu ?? 0;
        const requestedMem = budgetConfig.compute.requested_memory_gib ?? 0;
        const computeUsage = {
          resource_class: budgetConfig.compute.resource_class,
          vcpu_seconds: requestedVcpu * elapsedSeconds,
          memory_gib_seconds: requestedMem * elapsedSeconds,
        };

        const costs = calculateBilledCost({
          rate_card: budgetConfig.pricing.rate_card.rates,
          llm_usage: llmUsage,
          compute_usage: computeUsage,
          markup_pct: budgetConfig.pricing.markup_pct,
          billing_currency: currency,
          fx_usd_to_billing: budgetConfig.pricing.fx_usd_to_currency,
        });

        const billedTotal = Number(costs.billed_cost.total.amount) || 0;
        const byokUsd = Number(costs.base_cost_usd.llm_byok_usd.amount) || 0;
        const byokTotal = byokUsd * fxRate;

        const tokenBreakdown = calculateBudgetTokenBreakdown(
          budgetConfig.pricing.rate_card.rates,
          Array.from(llmUsageAgg.values()),
        );

        return {
          currency,
          ...tokenBreakdown,
          estimated_total: billedTotal + byokTotal,
          byok_total: byokTotal,
          billed_total: billedTotal,
        };
      };

      const triggerBudgetExceeded = async (
        input: { reason: string; trigger: string; state: BudgetState },
      ): Promise<void> => {
        if (budgetKillIssued) return;
        budgetKillIssued = true;

        const maxCost = budgetConfig?.max_cost ?? null;
        const maxTokens = budgetConfig?.max_tokens ?? null;
        const msgParts = [
          `BUDGET_EXCEEDED: ${input.reason}`,
          maxTokens ? `max_tokens=${maxTokens}` : null,
          maxCost ? `max_cost=${maxCost.currency} ${maxCost.amount}` : null,
          `est_total=${input.state.currency} ${input.state.estimated_total.toFixed(6)}`,
          `weighted_tokens=${input.state.weighted_tokens}`,
          `cache_read=${input.state.cache_read_tokens}(w=${formatCacheReadWeight(input.state.cache_read_token_weight)})`,
        ].filter(Boolean);
        budgetExceededError = msgParts.join(' ');

        if (budgetInterval) {
          clearInterval(budgetInterval);
          budgetInterval = null;
        }

        // Terminate the harness process (fail-fast). Escalate to SIGKILL after a grace window.
        try {
          harnessProcess.kill('SIGTERM');
        } catch {
          // ignore
        }
        setTimeout(() => {
          if (!budgetKillIssued) return;
          try {
            harnessProcess.kill('SIGKILL');
          } catch {
            // ignore
          }
        }, 5000);

        try {
          await this.logs.appendLog(invocation.attemptId, 'budget.exceeded', {
            trigger: input.trigger,
            reason: input.reason,
            max_tokens: maxTokens,
            max_cost: maxCost,
            currency: input.state.currency,
            estimated_total: input.state.estimated_total.toFixed(6),
            estimated_byok_total: input.state.byok_total.toFixed(6),
            estimated_billed_total: input.state.billed_total.toFixed(6),
            total_tokens: input.state.total_tokens,
            weighted_tokens: input.state.weighted_tokens,
            cache_read_tokens: input.state.cache_read_tokens,
            cache_read_token_weight: input.state.cache_read_token_weight,
            cache_read_tokens_excluded: input.state.cache_read_tokens_excluded,
          });
        } catch (err) {
          console.warn(`[budget] Failed to append budget.exceeded log: ${err instanceof Error ? err.message : String(err)}`);
        }
      };

      const appendBudgetSummary = async (trigger: string): Promise<void> => {
        if (!budgetConfig || budgetSummaryAppended) return;
        budgetSummaryAppended = true;
        const state = estimateBudgetState();
        if (!state) return;
        try {
          await this.logs.appendLog(invocation.attemptId, 'budget.summary', {
            trigger,
            max_tokens: budgetConfig.max_tokens ?? null,
            max_cost: budgetConfig.max_cost ?? null,
            currency: state.currency,
            estimated_total: state.estimated_total.toFixed(6),
            estimated_byok_total: state.byok_total.toFixed(6),
            estimated_billed_total: state.billed_total.toFixed(6),
            total_tokens: state.total_tokens,
            weighted_tokens: state.weighted_tokens,
            cache_read_tokens: state.cache_read_tokens,
            cache_read_token_weight: state.cache_read_token_weight,
            cache_read_tokens_excluded: state.cache_read_tokens_excluded,
          });
        } catch (err) {
          console.warn(`[budget] Failed to append budget.summary log: ${err instanceof Error ? err.message : String(err)}`);
        }
      };

      const maybeEnforceBudget = async (trigger: string): Promise<void> => {
        if (!budgetConfig || budgetKillIssued) return;
        const state = estimateBudgetState();
        if (!state) return;

        if (budgetConfig.max_tokens && state.weighted_tokens >= budgetConfig.max_tokens) {
          await triggerBudgetExceeded({ reason: 'max_tokens exceeded', trigger, state });
          return;
        }

        if (budgetConfig.max_cost && state.currency === budgetConfig.max_cost.currency && state.estimated_total >= budgetConfig.max_cost.amount) {
          await triggerBudgetExceeded({ reason: 'max_cost exceeded', trigger, state });
          return;
        }
      };

      const messageRelay = new EveMessageRelay(
        this.buildRelayDb(),
        invocation.jobId,
        invocation.parentJobId ?? null,
        invocation.agentId ?? null,
      );
      const isClaudeHarness = options.harness === 'claude' || options.harness === 'mclaude';
      let claudeApiKeySource: string | null = null;
      let claudeAuthFailureCandidate: { reason: string; apiKeySource?: string } | null = null;
      let claudeAuthFailureMessage: string | undefined;
      const maybeRecordClaudeAuthFailure = async (
        input: unknown,
        stream?: 'stdout' | 'stderr' | 'error',
      ): Promise<void> => {
        if (!isClaudeHarness || claudeAuthFailureCandidate) return;
        const apiKeySource = readClaudeApiKeySource(input);
        if (apiKeySource) {
          claudeApiKeySource = apiKeySource;
        }
        const failure = detectClaudeAuthFailure(input, stream ? { stream } : undefined);
        if (!failure) return;
        claudeAuthFailureCandidate = failure;
      };

      const rl = readline.createInterface({
        input: harnessProcess.stdout,
        crlfDelay: Infinity,
      });

      // Ensure stdout/stderr log writes are drained before we finalize results.
      let logChain: Promise<void> = Promise.resolve();
      const enqueue = (fn: () => Promise<void>) => {
        logChain = logChain.then(fn).catch((err) => {
          console.error('Failed processing harness log line:', err);
        });
      };

      if (budgetConfig) {
        // Periodic compute-budget enforcement even when no llm.call events are emitted.
        budgetInterval = setInterval(() => {
          enqueue(async () => {
            await maybeEnforceBudget('timer');
          });
        }, 2000);
      }

      const stdoutClosed = new Promise<void>((resolve) => rl.on('close', () => resolve()));

      rl.on('line', (line) => {
        if (!line.trim()) return;

        enqueue(async () => {
          try {
            const parsedLine = JSON.parse(line);
            const logType = parsedLine.type ?? 'event';
            await this.logs.appendLog(invocation.attemptId, logType, parsedLine);
            await maybeRecordClaudeAuthFailure(parsedLine);

            if (budgetConfig && logType === 'llm.call') {
              try {
                const provider = typeof parsedLine.provider === 'string' ? parsedLine.provider : 'unknown';
                const model = typeof parsedLine.model === 'string' ? parsedLine.model : 'unknown';
                const sourceRaw = typeof parsedLine.source === 'string' ? parsedLine.source : 'byok';
                const source: 'byok' | 'managed' = sourceRaw === 'managed' ? 'managed' : 'byok';
                const status = typeof parsedLine.status === 'string' ? parsedLine.status : 'ok';
                const ok = status === 'ok';
                const usage = parsedLine.usage as Record<string, unknown> | undefined;

                if (ok && usage) {
                  const key = `${source}:${provider}:${model}`;
                  const existing = llmUsageAgg.get(key) ?? {
                    provider,
                    model,
                    source,
                    usage: {
                      input_tokens: 0,
                      output_tokens: 0,
                      cache_read_tokens: 0,
                      cache_write_tokens: 0,
                      reasoning_tokens: 0,
                    },
                  };

                  existing.usage.input_tokens += Number(usage.input_tokens) || 0;
                  existing.usage.output_tokens += Number(usage.output_tokens) || 0;
                  existing.usage.cache_read_tokens += Number(usage.cache_read_tokens) || 0;
                  existing.usage.cache_write_tokens += Number(usage.cache_write_tokens) || 0;
                  existing.usage.reasoning_tokens += Number(usage.reasoning_tokens) || 0;
                  llmUsageAgg.set(key, existing);
                }

                await maybeEnforceBudget('llm.call');
              } catch (err) {
                console.warn(`[budget] Failed processing llm.call for enforcement: ${err instanceof Error ? err.message : String(err)}`);
              }
            }

            // Scan for eve-message blocks in assistant text
            await messageRelay.processEvent(parsedLine);
          } catch (parseError) {
            // Non-JSON line — check for raw eve-message fenced blocks
            await messageRelay.processLine(line);
            await maybeRecordClaudeAuthFailure(line, 'stdout');

            await this.logs.appendLog(invocation.attemptId, 'parse_error', {
              content: line,
              error:
                parseError instanceof Error
                  ? parseError.message
                  : String(parseError),
            });
          }
        });
      });

      harnessProcess.stderr.on('data', (data) => {
        const text = data.toString();
        enqueue(async () => {
          try {
            await maybeRecordClaudeAuthFailure(text, 'stderr');
            await this.logs.appendLog(invocation.attemptId, 'system_error', {
              content: text,
            });
          } catch (logError) {
            console.error('Failed to log stderr:', logError);
          }
        });
      });

      harnessProcess.on('close', async (exitCode, signal) => {
        await cancellation?.check();
        await finishCancellation();
        if (budgetInterval) {
          clearInterval(budgetInterval);
          budgetInterval = null;
        }

        // Wait for stdout/stderr log lines to be flushed before we compute results.
        await stdoutClosed;
        await logChain;
        await appendBudgetSummary('final');

        let finalExitCode: number;
        if (exitCode !== null) {
          finalExitCode = exitCode;
        } else {
          // Signal-killed: use Unix convention (128 + signal number)
          const signalCodes: Record<string, number> = {
            SIGTERM: 15, SIGKILL: 9, SIGINT: 2, SIGHUP: 1, SIGQUIT: 3,
          };
          const sigNum = signal ? (signalCodes[signal] ?? 1) : 1;
          finalExitCode = 128 + sigNum;
        }
        const durationMs = Date.now() - startTime;

        if (finalExitCode !== 0 && claudeAuthFailureCandidate) {
          claudeAuthFailureMessage = await this.emitClaudeAuthFailed(
            invocation,
            claudeAuthDecision ?? null,
            claudeAuthFailureCandidate,
            claudeApiKeySource,
          );
          onClaudeAuthFailure?.(claudeAuthFailureMessage);
        }

        try {
          await this.logs.appendLog(invocation.attemptId, 'system', {
            event: 'completed',
            exitCode: finalExitCode,
            durationMs,
          });
        } catch (logError) {
          console.error('Failed to log completion:', logError);
        }

        // Extract results from logs
        let extracted: ExtractedResult = {
          tokenInput: 0,
          tokenOutput: 0,
        };
        try {
          const logs = await this.logs.listLogs(invocation.attemptId);
          const logEntries = logs.map((l) => ({
            type: l.type,
            content: l.content as Record<string, unknown>,
          }));
          extracted = extractResults(logEntries);
        } catch (extractError) {
          console.error('Failed to extract results from logs:', extractError);
        }

        let errorMessage: string | undefined;
        if (finalExitCode !== 0) {
          errorMessage =
            extracted.errorMessage || `Process exited with code ${finalExitCode}`;
          if (claudeAuthFailureMessage) {
            errorMessage = extracted.errorMessage
              ? `${extracted.errorMessage}\n\n${claudeAuthFailureMessage}`
              : claudeAuthFailureMessage;
          }

          // Add helpful message for auth errors
          if (isAuthErrorMessage(errorMessage)) {
            errorMessage = `${errorMessage}\n\nTo fix: Run ./bin/eh docker auth && ./bin/eh docker stop && ./bin/eh docker start --no-build`;
          }
        }

        if (budgetExceededError) {
          errorMessage = budgetExceededError;
          if (finalExitCode === 0) finalExitCode = 1;
        }

        if (cancellation?.signal.aborted) { errorMessage = JOB_CANCELLED; finalExitCode = 130; }

        // Log harness lifecycle end
        await this.logLifecycleEvent(invocation.attemptId, 'harness', 'end', {
          harness: options.harness,
          permission: options.permission,
          ...(Object.keys(harnessOptions).length > 0
            ? { harness_options: harnessOptions }
            : {}),
          reasoning: options.reasoning,
          exit_code: finalExitCode,
        }, {
          duration_ms: durationMs,
          success: finalExitCode === 0,
          error: finalExitCode !== 0 ? errorMessage : undefined,
        });

        resolve({
          attemptId: invocation.attemptId,
          success: finalExitCode === 0,
          exitCode: finalExitCode,
          error: finalExitCode !== 0 ? errorMessage : undefined,
          resultText: extracted.resultText,
          resultJson: extracted.resultJson,
          durationMs,
          tokenInput: extracted.tokenInput,
          tokenOutput: extracted.tokenOutput,
        });
      });

      harnessProcess.on('error', async (error) => {
        await finishCancellation();
        if (budgetInterval) {
          clearInterval(budgetInterval);
          budgetInterval = null;
        }

        const durationMs = Date.now() - startTime;

        await appendBudgetSummary('spawn_error');

        try {
          await this.logs.appendLog(invocation.attemptId, 'spawn_error', {
            error: error.message,
          });
        } catch (logError) {
          console.error('Failed to log spawn error:', logError);
        }

        resolve({
          attemptId: invocation.attemptId,
          success: false,
          exitCode: 1,
          error: `Failed to spawn ${options.harness}: ${error.message}`,
          durationMs,
          tokenInput: 0,
          tokenOutput: 0,
        });
      });
    });
  }
}

function uniqueAttachmentName(safeName: string, used: Set<string>): string {
  let filename = safeName;
  let suffix = 1;
  while (used.has(filename)) {
    const dot = safeName.lastIndexOf('.');
    filename = dot > 0 ? `${safeName.slice(0, dot)}-${suffix}${safeName.slice(dot)}` : `${safeName}-${suffix}`;
    suffix += 1;
  }
  used.add(filename);
  return filename;
}
