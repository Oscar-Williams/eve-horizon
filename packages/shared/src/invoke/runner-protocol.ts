/**
 * The protocol between the worker and a runner pod.
 *
 * A runner pod runs one job and holds no platform credential: no database URL
 * and no internal key. The worker does every database and internal-API call
 * the job needs, then POSTs the result to the pod's one route,
 * `POST /runner/submit`, as a {@link RunnerSubmit}. The runner reports back
 * only through the push-only attempt routes
 * (`/jobs/:job/attempts/:attempt/runner/...`), with the attempt's own job
 * token, and ends with one `result`.
 *
 * The worker authenticates its submit with a key, presented in
 * `x-eve-runner-key`, whose SHA-256 alone the pod carries:
 *
 * - a plain pod: a key made for that pod (`EVE_RUNNER_INBOUND_KEY_SHA256`);
 * - a pod from a warm pool, which cannot carry per-job env: the worker's pool
 *   key (`EVE_RUNNER_POOL_KEY_SHA256`, in the SandboxTemplate). Only the
 *   worker holds the key: `EVE_RUNNER_POOL_KEY` when set, else an HMAC of its
 *   internal core key (or the legacy key) with a fixed label. Changing either
 *   changes the templates the worker renders, and the warm pools (update
 *   strategy Recreate) replace their pods.
 *
 * A runner with neither hash takes no submit.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { INTERNAL_KEY_ENV } from '../api-client/internal-keys.js';
import type { SecretResolveItem } from '../schemas/secret.js';
import type { HarnessInvocation } from '../types/harness.js';
import type { JobGit, ResolvedGitMetadata } from '../schemas/git-controls.js';
import type { SecurityProfile } from '../security/profile.js';

/** The port a runner serves on (the worker's port, so probes and policies keep one number). */
export const RUNNER_PORT = 4749;
export const RUNNER_SUBMIT_PATH = '/runner/submit';
export const RUNNER_INBOUND_KEY_HEADER = 'x-eve-runner-key';
export const RUNNER_INBOUND_KEY_SHA256_ENV = 'EVE_RUNNER_INBOUND_KEY_SHA256';
/** The SHA-256 of the worker's pool key, in a warm-pool template. */
export const RUNNER_POOL_KEY_SHA256_ENV = 'EVE_RUNNER_POOL_KEY_SHA256';
/** A dedicated pool key for the worker (a Secret value); derived from the internal key when unset. */
export const RUNNER_POOL_KEY_ENV = 'EVE_RUNNER_POOL_KEY';
const POOL_KEY_LABEL = 'eve-runner-pool-key/v1';

/** A fresh inbound key for one runner pod, and the hash its spec carries. */
export function createRunnerInboundKey(): { key: string; sha256: string } {
  const key = randomBytes(32).toString('base64url');
  return { key, sha256: sha256Hex(key) };
}

/** Whether a presented inbound key matches the pod's hash (constant time). */
export function runnerInboundKeyMatches(presented: string | undefined, sha256: string | undefined): boolean {
  if (!presented || !sha256 || !/^[0-9a-f]{64}$/.test(sha256)) return false;
  return timingSafeEqual(Buffer.from(sha256Hex(presented), 'hex'), Buffer.from(sha256, 'hex'));
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

/**
 * The worker's pool key and the hash warm-pool templates carry: the
 * dedicated `EVE_RUNNER_POOL_KEY`, else an HMAC of the internal core key (or
 * the legacy `EVE_INTERNAL_API_KEY`) with a fixed label. Null when the worker
 * holds none of them: it then claims no warm pod.
 */
export function runnerPoolKey(env: NodeJS.ProcessEnv = process.env): { key: string; sha256: string } | null {
  const dedicated = env[RUNNER_POOL_KEY_ENV]?.trim();
  const base = env[INTERNAL_KEY_ENV.core]?.trim() || env.EVE_INTERNAL_API_KEY?.trim();
  const key = dedicated || (base ? createHmac('sha256', base).update(POOL_KEY_LABEL).digest('base64url') : '');
  return key ? { key, sha256: sha256Hex(key) } : null;
}

/**
 * Whether a submit's key is one this runner accepts: its own inbound key, or
 * (a warm-pool pod) the worker's pool key, each checked against the hash the
 * pod carries. A runner with neither hash accepts nothing.
 */
export function runnerSubmitKeyMatches(presented: string | undefined, env: NodeJS.ProcessEnv = process.env): boolean {
  return runnerInboundKeyMatches(presented, env[RUNNER_INBOUND_KEY_SHA256_ENV])
    || runnerInboundKeyMatches(presented, env[RUNNER_POOL_KEY_SHA256_ENV]);
}

/**
 * A secret delivered to a runner. `clone_only` marks the platform's
 * credential for the workspace clone: the runner uses it for the clone and
 * drops it before any job code runs.
 */
export type RunnerSecret = SecretResolveItem;

/** A file the worker rendered for the job's `.eve/` context, written into the repo before the harness runs. */
export interface RunnerContextFile {
  /** Path relative to the repository root; always under `.eve/`. */
  path: string;
  content_b64: string;
}

/** One resource ref, resolved by the worker. The runner writes it, or downloads it from `url`. */
export interface RunnerResource {
  uri: string;
  label?: string;
  required: boolean;
  mount_path: string;
  mime_type?: string;
  metadata?: Record<string, unknown>;
  /** Set when the worker could not resolve the ref; the runner records it as missing. */
  error_code?: string;
  content_b64?: string;
  content_hash?: string;
  version?: number | null;
  /** A presigned GET URL; the runner hashes what it downloads. */
  url?: string;
}

/** A chat attachment, presigned by the worker. */
export interface RunnerChatAttachment {
  filename: string;
  url: string;
  index: Record<string, unknown>;
}

export interface RunnerBudgetConfig {
  max_tokens: number | null;
  max_cost: { currency: string; amount: number } | null;
  pricing: {
    rate_card: { name: string; version: number; effective_at: string; rates: unknown };
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
}

/** What the job's message relay may look up: its own and its parent's hints, and the threads they name. */
export interface RunnerRelayLookups {
  jobs: Record<string, { hints: Record<string, unknown> | null; project_id: string | null }>;
  threads: Record<string, string | null>;
}

/** An agent job, prepared by the worker. */
export interface PreparedAgentJob {
  /** The effective invocation: manifest defaults applied, app CLIs resolved. */
  invocation: HarnessInvocation;
  secrets: RunnerSecret[];
  git_ref?: { ref: string; source: 'env_release' | 'manifest' | 'project_default' | 'explicit' } | null;
  skip_workspace_skills?: boolean;
  resources?: RunnerResource[];
  chat_attachments?: RunnerChatAttachment[];
  context_files?: RunnerContextFile[];
  /** The job's app APIs and links, with link tokens already minted. */
  app_apis?: Array<Record<string, unknown>>;
  budget?: RunnerBudgetConfig | null;
  relay?: RunnerRelayLookups;
  /** The job's actor, for attachment ownership checks the runner repeats. */
  actor_user_id?: string | null;
  /**
   * The project's profile for each rule the runner applies itself
   * (RUNNER_DECIDED_RULES), decided by the worker: a runner has no database.
   */
  rule_profiles?: Record<string, SecurityProfile>;
  /** For a chat job: the chat thread its eve-message progress goes to. */
  chat?: { thread_id: string } | null;
}

/** A script step (or `action: run`), prepared by the worker. */
export interface PreparedScriptJob {
  command: string;
  timeout_seconds: number;
  /** Timeout error code: script_timeout or action_run_timeout. */
  timeout_code?: string;
  repo_url: string;
  default_branch: string;
  git?: JobGit | null;
  git_ref?: { ref: string; source: 'env_release' | 'manifest' | 'project_default' | 'explicit' } | null;
  env_name?: string | null;
  env_namespace?: string | null;
  env_overrides?: Record<string, string> | null;
  strict_env_overrides?: boolean;
  run_id?: string | null;
  parent_id?: string | null;
  toolchains?: string[];
  app_link_env?: Record<string, string>;
  secrets: RunnerSecret[];
  relay?: RunnerRelayLookups;
}

/** The body of `POST /runner/submit`. */
export interface RunnerSubmit {
  kind: 'agent' | 'script';
  job_id: string;
  attempt_id: string;
  project_id: string;
  /** The attempt-bound job token: the job uses it, and the runner reports with it. */
  job_token: string;
  /** Where the runner reports (the API's public port). */
  api_url: string;
  /**
   * The runner's egress self-check before it uses the token: `enforce` fails
   * the job when the metadata server or the Kubernetes API answers, `audit`
   * records it, `off` skips it.
   */
  self_check?: 'enforce' | 'audit' | 'off';
  agent?: PreparedAgentJob;
  script?: PreparedScriptJob;
}

/** What a runner reports as its attempt's result (once). */
export interface RunnerResultReport {
  success: boolean;
  exit_code: number;
  error?: string;
  error_code?: string;
  result_text?: string;
  result_json?: unknown;
  duration_ms?: number;
  token_input?: number;
  token_output?: number;
  stdout?: string;
  stderr?: string;
  git?: ResolvedGitMetadata;
}

/** Top-level runtime_meta fields a runner may report; the rest belong to the platform. */
export const RUNNER_RUNTIME_META_KEYS = ['orgfs_mount', 'resource_hydration', 'resource_index_path', 'browser', 'toolchains', 'self_check'] as const;

/** Event types a runner may emit for its attempt. */
export const RUNNER_EVENT_TYPES = [
  'system.resource.hydration.started',
  'system.resource.hydration.completed',
  'system.resource.hydration.failed',
  // A finding for a rule the runner applies: payload { rule, detail }.
  'security.finding',
] as const;

/** Project rules a runner applies itself, with the profile the worker decided. */
export const RUNNER_DECIDED_RULES = ['harness.checkout_settings'] as const;

/** Rules a runner may record findings for (through its events route). */
export const RUNNER_FINDING_RULES: readonly string[] = [...RUNNER_DECIDED_RULES];

/** The one credential a runner may write back: a refreshed Codex auth.json. */
export const RUNNER_WRITABLE_CREDENTIALS = ['CODEX_AUTH_JSON_B64'] as const;

/** Light validation of a submit body; returns an error message or null. */
export function runnerSubmitError(body: unknown): string | null {
  if (!body || typeof body !== 'object') return 'body must be an object';
  const submit = body as Partial<RunnerSubmit>;
  for (const field of ['job_id', 'attempt_id', 'project_id', 'job_token', 'api_url'] as const) {
    if (typeof submit[field] !== 'string' || !submit[field]) return `${field} is required`;
  }
  if (submit.kind === 'agent') return submit.agent?.invocation ? null : 'agent.invocation is required';
  if (submit.kind === 'script') return typeof submit.script?.command === 'string' ? null : 'script.command is required';
  return 'kind must be agent or script';
}
