/**
 * Shared workspace secret resolution and materialization.
 *
 * Extracted from agent-runtime invoke.service.ts (lines 481-637).
 * Both agent-runtime and worker can call these standalone functions
 * instead of duplicating secret handling in each service.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import type { SecretResolveItem } from '../schemas/secret.js';
import type { HarnessInvocation } from '../types/harness.js';
import { resolveProjectSecrets } from '../api-client/secret-client.js';
import { buildAuthenticatedHttpsUrl } from '../git/clone-url.js';
import type { LifecycleLogger, GitAuth } from './types.js';
import { sanitizeSecretFilename } from '../harnesses/invoke-utils.js';
import { cleanupJobUserHome } from './job-user-home.js';

/**
 * Per-attempt folders that hold secrets outside the workspace: file-type
 * secrets, and the git SSH key used for the workspace clone. Both are keyed by
 * attempt id and removed when the attempt ends (cleanupJobSecretArtifacts).
 */
const SECRET_FILES_ROOT = path.join(os.tmpdir(), 'eve', 'job-secrets');
const GIT_KEYS_ROOT = path.join(os.tmpdir(), 'eve', 'git-keys');
const JOB_SECRET_ROOTS = [SECRET_FILES_ROOT, GIT_KEYS_ROOT];

function attemptKey(attemptId: string | undefined): string {
  return attemptId || 'unknown-attempt';
}

/**
 * Resolve all secrets for a project via the Eve API.
 *
 * Emits lifecycle events when a `logLifecycle` callback and `attemptId` are
 * provided. Throws on resolution failure so callers can fail fast.
 */
export async function resolveSecrets(
  projectId: string,
  logLifecycle?: LifecycleLogger,
  userId?: string,
  attemptId?: string,
): Promise<SecretResolveItem[]> {
  const startTime = Date.now();
  if (attemptId && logLifecycle) {
    await logLifecycle(attemptId, 'secrets', 'start', {
      project_id: projectId,
    });
  }

  const result = await resolveProjectSecrets(projectId, { userId });

  if (attemptId && logLifecycle) {
    if (!result.resolved) {
      console.error(`Secret resolution failed for project ${projectId}: ${result.error}`);
      await logLifecycle(
        attemptId,
        'secrets',
        'end',
        { error: result.error ?? 'unknown' },
        { duration_ms: Date.now() - startTime, success: false, error: result.error ?? 'unknown' },
      );
      throw new Error(`Secret resolution failed: ${result.error}`);
    } else {
      await logLifecycle(
        attemptId,
        'secrets',
        'end',
        { project_id: projectId, resolved_count: result.secrets.length },
        { duration_ms: Date.now() - startTime, success: true },
      );
    }
  } else if (!result.resolved) {
    // No attemptId for lifecycle logging, but still fail fast
    console.error(`Secret resolution failed for project ${projectId}: ${result.error}`);
    throw new Error(`Secret resolution failed: ${result.error}`);
  }

  return result.secrets;
}

/**
 * Derive git authentication for the platform's own git calls (clone, fetch,
 * push) from resolved secrets and the invocation's repo URL.
 *
 * Pass every resolved secret: the workspace clone may use a credential the
 * job itself does not receive. For `git@` / `ssh://` URLs the SSH key is
 * written outside the workspace and named in `GIT_SSH_COMMAND`. For GitHub
 * HTTPS URLs the token is embedded in the clone URL (and so in the clone's
 * `.git/config`, where the agent can use it) only when the job may hold it:
 * with no secrets allowlist, or one that names it. Otherwise it travels as an
 * auth header in the env of the platform's git calls only. Returns
 * `undefined` when no applicable credential is found.
 */
export async function prepareGitAuth(
  invocation: HarnessInvocation,
  secrets: SecretResolveItem[],
): Promise<GitAuth | undefined> {
  const repoUrl = invocation.repoUrl;
  if (!repoUrl) return undefined;

  const { sshSecret, githubToken } = gitCredentials(secrets);

  if (sshSecret && isSshRepoUrl(repoUrl)) {
    const keyDir = path.join(GIT_KEYS_ROOT, attemptKey(invocation.attemptId));
    await fs.mkdir(keyDir, { recursive: true, mode: 0o700 });
    const keyPath = path.join(keyDir, 'git_ssh_key');
    await fs.writeFile(keyPath, sshSecret.value, { mode: 0o600 });
    return {
      env: {
        GIT_SSH_COMMAND: `ssh -i ${keyPath} -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new`,
      },
    };
  }

  if (githubToken && repoUrl.startsWith('http')) {
    const jobMayHoldToken = !invocation.secrets_allowlist || invocation.secrets_allowlist.includes(githubToken.key);
    if (jobMayHoldToken) {
      const cloneUrl = buildAuthenticatedHttpsUrl(repoUrl, githubToken.value);
      if (cloneUrl !== repoUrl) {
        return { cloneUrl };
      }
    } else {
      const env = githubAuthHeaderEnv(repoUrl, githubToken.value);
      if (env) return { env };
    }
  }

  return undefined;
}

/**
 * Once the workspace is prepared, delete an SSH key the job may not hold (a
 * secrets allowlist that leaves it out), unless the platform still needs it to
 * push when the harness finishes. The harness runs as the same user and could
 * otherwise read the key from its folder.
 */
export async function releaseCloneOnlyGitKey(
  invocation: HarnessInvocation,
  secrets: SecretResolveItem[],
): Promise<void> {
  if (!cloneOnlyGitCredential(invocation, secrets)) return;
  await fs.rm(path.join(GIT_KEYS_ROOT, attemptKey(invocation.attemptId)), { recursive: true, force: true });
}

/**
 * Refuse a job that would need a clone-only git credential (one its secrets
 * allowlist leaves out) anywhere but a fresh clone. Once the harness has run,
 * or in a workspace an earlier attempt used, the repository's config is the
 * job's to write: a filter driver, `gpg.program` or an `http.proxy` with
 * `sslVerify=false` would see the credential of any git command that carried
 * it. So such a job may not push (`git.push` other than `never`) and may not
 * reuse a workspace (session mode, or a repo already on disk). Call it before
 * preparing the workspace.
 */
export async function assertCloneOnlyGitCredentialSafe(
  invocation: HarnessInvocation,
  secrets: SecretResolveItem[],
): Promise<void> {
  const credential = cloneOnlyGitCredential(invocation, secrets);
  if (!credential) return;
  const why = `the job's secrets allowlist leaves out ${credential}, which the platform holds only to clone the workspace`;
  const push = (invocation.git as { push?: string } | undefined)?.push;
  if (push && push !== 'never') {
    throw new Error(`git_credential_not_allowlisted: git.push=${push} is refused because ${why}; add ${credential} to the allowlist or set git.push: never`);
  }
  const reused = invocation.workspace?.mode === 'session'
    || await fs.stat(path.join(invocation.workspacePath, 'repo')).then(() => true, () => false);
  if (reused) {
    throw new Error(`git_credential_not_allowlisted: a reused workspace is refused because ${why}; add ${credential} to the allowlist or run in a fresh workspace`);
  }
}

/** The key of the git credential the platform would use for this repo but the job may not hold, if any. */
function cloneOnlyGitCredential(invocation: HarnessInvocation, secrets: SecretResolveItem[]): string | null {
  const allowlist = invocation.secrets_allowlist;
  const repoUrl = invocation.repoUrl;
  if (!allowlist || !repoUrl) return null;
  const { sshSecret, githubToken } = gitCredentials(secrets);
  const credential = isSshRepoUrl(repoUrl)
    ? sshSecret
    : repoUrl.startsWith('http') ? githubToken : undefined;
  return credential && !allowlist.includes(credential.key) ? credential.key : null;
}

function gitCredentials(secrets: SecretResolveItem[]): {
  sshSecret?: SecretResolveItem;
  githubToken?: SecretResolveItem;
} {
  return {
    sshSecret: secrets.find((secret) => secret.type === 'ssh_key'),
    githubToken:
      secrets.find((secret) => secret.type === 'github_token') ??
      secrets.find((secret) => ['GITHUB_TOKEN', 'GH_TOKEN'].includes(secret.key)),
  };
}

function isSshRepoUrl(repoUrl: string): boolean {
  return repoUrl.startsWith('git@') || repoUrl.startsWith('ssh://');
}

/**
 * Git config, as env, that sends a GitHub token as a basic-auth header to the
 * repo's host: the same `x-access-token:<token>` credential the clone URL
 * would carry, without writing it into the clone's `.git/config`.
 */
function githubAuthHeaderEnv(repoUrl: string, token: string): Record<string, string> | undefined {
  const trimmed = token.trim();
  if (!trimmed) return undefined;
  let origin: string;
  try {
    const url = new URL(repoUrl);
    if (!url.hostname.includes('github.com')) return undefined;
    origin = `${url.protocol}//${url.host}/`;
  } catch {
    return undefined;
  }
  const basic = Buffer.from(`x-access-token:${trimmed}`).toString('base64');
  return {
    GIT_CONFIG_COUNT: '1',
    GIT_CONFIG_KEY_0: `http.${origin}.extraheader`,
    GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${basic}`,
  };
}

/**
 * Write secret values into the environment and (for file-type secrets)
 * onto disk.
 *
 * Plain secrets become environment variables. File/SSH secrets are written
 * to a temp directory outside the workspace so hooks can reference them by
 * path without leaking values into the repo tree.
 *
 * Returns the augmented env and (currently always `null`) secrets file path.
 */
export async function materializeSecrets(
  repoPath: string,
  invocation: HarnessInvocation,
  secrets: SecretResolveItem[],
  orgRootPath: string | null,
): Promise<{ env: NodeJS.ProcessEnv; secretsFilePath: string | null }> {
  const env: NodeJS.ProcessEnv = {
    EVE_JOB_ID: invocation.jobId,
    EVE_ATTEMPT_ID: invocation.attemptId,
    EVE_PROJECT_ID: invocation.projectId,
    EVE_REPO_PATH: repoPath,
  };

  if (invocation.agentId) {
    env.EVE_AGENT_ID = invocation.agentId;
  }
  if (orgRootPath) {
    env.EVE_ORG_ROOT = orgRootPath;
  }

  if (secrets.length === 0) {
    return { env, secretsFilePath: null };
  }

  // File-type secrets are written outside the workspace so hooks can reference
  // them by path. Plain secrets are passed as env vars.
  const secretFilesDir = path.join(SECRET_FILES_ROOT, attemptKey(invocation.attemptId));

  for (const secret of secrets) {
    if (secret.type === 'file' || secret.type === 'ssh_key') {
      await fs.mkdir(secretFilesDir, { recursive: true });
      const fileName = sanitizeSecretFilename(secret.key);
      const filePath = path.join(secretFilesDir, fileName);
      await fs.writeFile(filePath, secret.value, { mode: 0o600 });
      env[secret.key] = filePath;
    } else {
      env[secret.key] = secret.value;
    }
  }

  return { env, secretsFilePath: null };
}

// Matches one ${secret.KEY} placeholder. Zod validation already rejects any
// other ${...} expression before the value lands on the job row, but the
// runtime helpers remain defensive so a malformed payload never reaches the
// harness with a half-expanded value.
const SECRET_PLACEHOLDER = /\$\{secret\.([A-Z_][A-Z0-9_]*)\}/g;
const ANY_PLACEHOLDER = /\$\{[^}]+\}/;

/**
 * Return the deduplicated list of secret keys referenced by any value in
 * `raw` via `${secret.KEY}` placeholders. Keys appear in first-seen order.
 */
export function extractSecretRefs(raw: Record<string, string>): string[] {
  const seen = new Set<string>();
  const ordered: string[] = [];
  for (const value of Object.values(raw)) {
    SECRET_PLACEHOLDER.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = SECRET_PLACEHOLDER.exec(value)) !== null) {
      const key = match[1];
      if (!seen.has(key)) {
        seen.add(key);
        ordered.push(key);
      }
    }
  }
  return ordered;
}

/**
 * Interpolate ${secret.KEY} placeholders against already-resolved project
 * secrets. Pure — does not call the API or read disk. Missing keys are
 * returned in `missing` (caller fails fast with `missing_secret_override`).
 *
 * Any ${...} expression that isn't a well-formed ${secret.KEY} is rejected
 * by throwing, since the API-layer validator should have already scrubbed
 * it. Never logs resolved values.
 */
export function interpolateEnvOverrides(
  raw: Record<string, string>,
  resolvedSecrets: SecretResolveItem[],
): { resolved: Record<string, string>; missing: string[] } {
  const secretMap = new Map<string, string>();
  for (const secret of resolvedSecrets) {
    secretMap.set(secret.key, secret.value);
  }

  const resolved: Record<string, string> = {};
  const missingSet = new Set<string>();

  for (const [key, value] of Object.entries(raw)) {
    SECRET_PLACEHOLDER.lastIndex = 0;
    const resolvedValue = value.replace(SECRET_PLACEHOLDER, (_match, ref: string) => {
      const lookup = secretMap.get(ref);
      if (lookup === undefined) {
        missingSet.add(ref);
        return '';
      }
      return lookup;
    });

    if (ANY_PLACEHOLDER.test(resolvedValue)) {
      throw new Error(
        `env_overrides value for ${key} contains an unsupported expression; only \${secret.KEY} is allowed`,
      );
    }

    resolved[key] = resolvedValue;
  }

  return { resolved, missing: Array.from(missingSet) };
}

/**
 * Remove any secret artifacts that may have been written inside the
 * workspace tree (legacy `.eve/secrets.env` and `.eve/secrets/` directory).
 *
 * Called during workspace cleanup so secrets are never left on disk after
 * a job completes.
 */
export async function cleanupWorkspaceSecretArtifacts(repoPath: string): Promise<void> {
  const artifactPaths = [
    path.join(repoPath, '.eve', 'secrets.env'),
    path.join(repoPath, '.eve', 'secrets'),
  ];

  await Promise.all(
    artifactPaths.map((artifactPath) =>
      fs.rm(artifactPath, { recursive: true, force: true }).catch((error) => {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          throw error;
        }
      }),
    ),
  );
}

/**
 * Delete every secret an attempt wrote to disk: file-type secrets, git SSH
 * keys, and the per-job HOME holding the Eve, Claude and gh credentials.
 *
 * Both execution paths call this when an attempt ends, whatever the outcome,
 * so nothing outlives the job on a pod shared with other jobs. Best-effort:
 * a failure is logged, never thrown over the job's result.
 */
export async function cleanupJobSecretArtifacts(
  invocation: Pick<HarnessInvocation, 'attemptId' | 'workspacePath'>,
): Promise<void> {
  const key = attemptKey(invocation.attemptId);
  const targets: string[] = [];
  for (const root of JOB_SECRET_ROOTS) {
    const dir = path.resolve(root, key);
    // An attempt id is a single path segment; refuse anything that escapes its root.
    if (path.dirname(dir) === path.resolve(root)) targets.push(dir);
  }
  if (invocation.workspacePath) {
    // Where earlier versions wrote the clone's SSH key; a reused session workspace may still hold one.
    targets.push(path.join(invocation.workspacePath, '.eve', 'git_ssh_key'));
  }

  await Promise.all(targets.map((target) =>
    fs.rm(target, { recursive: true, force: true }).catch((error) => {
      console.warn(`[secrets] Failed to remove ${target}: ${error instanceof Error ? error.message : String(error)}`);
    }),
  ));
  if (invocation.attemptId && path.basename(invocation.attemptId) === invocation.attemptId) {
    await cleanupJobUserHome(invocation.attemptId);
  }
}
