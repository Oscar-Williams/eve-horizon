/**
 * Codex auth provenance and writeback.
 *
 * Provenance: a redacted `codex_auth_selected` record of which credential an
 * attempt used (source, key name, scope — never the value), written to the
 * attempt log so `eve auth verify --harness codex` and job receipts can show it
 * after the runner pod is gone.
 *
 * Writeback: after harness execution, read back auth.json from the Codex
 * config directory, compare to the original base64, and update the secret if
 * changed. Failures are non-fatal — logged at warn level and swallowed.
 */

import * as fs from 'fs/promises';
import * as path from 'path';
import * as os from 'os';
import { updateSecret } from '../api-client/secret-client.js';
import type { SecretResolveItem } from '../schemas/secret.js';

/** Credential sources in the order the runtime tries them. */
export const CODEX_AUTH_SOURCES = ['api_key', 'auth_json', 'oauth_access_token', 'preexisting'] as const;
export type CodexAuthSource = (typeof CODEX_AUTH_SOURCES)[number];

/** Redacted record of the credential a codex-family attempt selected. Carries no secret values. */
export interface CodexAuthSelection {
  source: CodexAuthSource;
  /** Name of the secret the credential came from; absent for pre-existing auth files. */
  secret_key?: string;
  scope_type?: string;
  scope_id?: string;
}

/**
 * Describe a selection from the secret that backed it. Only the key name and
 * scope are copied; fields the secret does not carry are omitted.
 */
export function selectedCodexAuth(
  source: CodexAuthSource,
  secret?: Pick<SecretResolveItem, 'key'> & Partial<Pick<SecretResolveItem, 'scope_type' | 'scope_id'>> | null,
): CodexAuthSelection {
  const selection: CodexAuthSelection = { source };
  if (!secret) return selection;
  selection.secret_key = secret.key;
  if (secret.scope_type) selection.scope_type = secret.scope_type;
  if (secret.scope_id) selection.scope_id = secret.scope_id;
  return selection;
}

export async function writeBackCodexAuth(
  originalB64: string,
  scopeType: 'user' | 'org' | 'project',
  scopeId: string,
  codexHome?: string,
  /** Where the refreshed value goes; the internal secrets API when omitted. A runner pod passes its credential route. */
  write: (newB64: string) => Promise<void> = (newB64) => updateSecret(scopeType, scopeId, 'CODEX_AUTH_JSON_B64', newB64),
): Promise<void> {
  try {
    // Only the job's own CODEX_HOME: the runtime's HOME is shared by every job on it.
    if (!codexHome) return;
    const authPaths = [path.join(codexHome, 'auth.json')];

    let freshestContent: string | null = null;
    let freshestExpiry = -1;

    for (const authPath of authPaths) {
      try {
        const content = await fs.readFile(authPath, 'utf-8');
        const parsed = JSON.parse(content) as Record<string, unknown>;
        const tokens = parsed.tokens as Record<string, unknown> | undefined;
        const expiresAt = typeof tokens?.expires_at === 'number' ? tokens.expires_at : 0;
        if (freshestContent === null || expiresAt > freshestExpiry) {
          freshestContent = content;
          freshestExpiry = expiresAt;
        }
      } catch {
        // File missing or invalid — skip
      }
    }

    if (!freshestContent) return;

    const newB64 = Buffer.from(freshestContent, 'utf-8').toString('base64');
    if (newB64 === originalB64) return;

    console.log(`[codex-writeback] Token refreshed — updating secret ${scopeType}/${scopeId}/CODEX_AUTH_JSON_B64`);
    await write(newB64);
  } catch (err) {
    console.warn(`[codex-writeback] Failed to write back Codex auth: ${err instanceof Error ? err.message : String(err)}`);
  }
}

/**
 * Where a job's Codex auth.json is written: the harness config dir
 * (CODEX_HOME) and the per-job HOME, which the harness runs with. Never the
 * runtime's own HOME: every job on the runtime shares it, so a file there
 * would outlive the job and reach the next one.
 */
export function jobCodexAuthDirs(configDir: string | undefined, jobUserHome: string | undefined): string[] {
  const dirs = [
    configDir,
    jobUserHome ? path.join(jobUserHome, '.codex') : undefined,
    jobUserHome ? path.join(jobUserHome, '.code') : undefined,
  ].filter((dir): dir is string => Boolean(dir));
  return [...new Set(dirs)];
}

/**
 * Pre-existing auth.json a job may fall back to when no Codex credential
 * secret applies: only one already in the harness config dir (from the repo
 * or an operator-set CODEX_HOME), and never for a job with a secrets
 * allowlist, which uses only the credentials it names.
 */
export function preexistingCodexAuthPaths(
  configDir: string | undefined,
  invocation: { secrets_allowlist?: string[]; credentials_from_secrets_only?: boolean },
): string[] {
  if (!mayUseRuntimeCodexAuth(invocation) || !configDir) return [];
  return [path.join(configDir, 'auth.json')];
}

/**
 * Whether a job may fall back to Codex auth the runtime holds itself (an
 * auth.json already in the config dir, or the operator's own env or login):
 * not for a job with a secrets allowlist, nor under the project's `strict`
 * profile, where credentials come only from the job's secrets.
 */
export function mayUseRuntimeCodexAuth(invocation: {
  secrets_allowlist?: string[];
  credentials_from_secrets_only?: boolean;
}): boolean {
  return !invocation.secrets_allowlist && !invocation.credentials_from_secrets_only;
}

/**
 * Remove the Codex auth.json files earlier versions wrote into the runtime's
 * own HOME, where every later job could read them. Only in k8s, where HOME is
 * the service's: a runtime started locally runs as a developer, whose own
 * login must stay.
 */
export async function removeStaleServiceHomeCodexAuth(options: {
  home?: string;
  runtime?: string;
} = {}): Promise<void> {
  const runtime = options.runtime ?? process.env.EVE_RUNTIME;
  if (runtime !== 'k8s') return;
  const home = options.home ?? (process.env.HOME || os.homedir());
  await Promise.all(['.codex', '.code'].map((dir) =>
    fs.rm(path.join(home, dir, 'auth.json'), { force: true }).catch((error) => {
      console.warn(`[codex-auth] Failed to remove stale ${dir}/auth.json: ${error instanceof Error ? error.message : String(error)}`);
    }),
  ));
}

/**
 * Write a job's Codex auth.json to its harness config dir and per-job HOME.
 * When the config dir is inside the repo (the default
 * `<repo>/.agent/harnesses/codex`), the file is added to `.git/info/exclude`
 * so a commit policy's `git add -A` never commits or pushes it.
 */
export async function writeJobCodexAuth(
  content: string,
  target: { configDir?: string; jobUserHome?: string; repoPath?: string },
): Promise<void> {
  for (const dir of jobCodexAuthDirs(target.configDir, target.jobUserHome)) {
    const authPath = path.join(dir, 'auth.json');
    try {
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(authPath, content, { mode: 0o600 });
    } catch (error) {
      console.warn(`[codex-auth] Failed to write auth.json to ${authPath}: ${String(error)}`);
    }
  }
  if (target.configDir && target.repoPath) {
    await excludeFromGit(target.repoPath, path.join(target.configDir, 'auth.json'));
  }
}

async function excludeFromGit(repoPath: string, file: string): Promise<void> {
  const relative = path.relative(repoPath, file);
  if (!relative || relative.startsWith('..') || path.isAbsolute(relative)) return;
  const gitDir = path.join(repoPath, '.git');
  const isDir = await fs.stat(gitDir).then((stat) => stat.isDirectory(), () => false);
  if (!isDir) return;
  const excludePath = path.join(gitDir, 'info', 'exclude');
  const line = `/${relative.split(path.sep).join('/')}`;
  try {
    const existing = await fs.readFile(excludePath, 'utf-8').catch(() => '');
    if (existing.split('\n').includes(line)) return;
    await fs.mkdir(path.dirname(excludePath), { recursive: true });
    const prefix = existing && !existing.endsWith('\n') ? '\n' : '';
    await fs.appendFile(excludePath, `${prefix}${line}\n`);
  } catch (error) {
    console.warn(`[codex-auth] Failed to exclude ${line} from git: ${String(error)}`);
  }
}

/**
 * Codex auth the operator provides, for jobs without a secrets allowlist:
 *
 * - the service's own environment (`CODEX_AUTH_JSON` / `CODEX_AUTH_JSON_B64`,
 *   base64 auth.json; or `CODEX_OAUTH_ACCESS_TOKEN` with optional
 *   `CODEX_OAUTH_ID_TOKEN` / `CODEX_OAUTH_ACCOUNT_ID`). Job code can neither
 *   read nor change it, unlike a file in a directory the service user owns;
 * - outside k8s only (services run on a developer's machine), the developer's
 *   own `codex login` in `~/.codex/auth.json` or `~/.code/auth.json`, read and
 *   never written.
 *
 * Returns the auth.json content, or null.
 */
export async function operatorCodexAuth(options: {
  env?: NodeJS.ProcessEnv;
  home?: string;
  runtime?: string;
} = {}): Promise<string | null> {
  const env = options.env ?? process.env;
  const b64 = env.CODEX_AUTH_JSON || env.CODEX_AUTH_JSON_B64;
  if (b64) return Buffer.from(b64, 'base64').toString('utf-8');
  if (env.CODEX_OAUTH_ACCESS_TOKEN) {
    return JSON.stringify({
      tokens: {
        access_token: env.CODEX_OAUTH_ACCESS_TOKEN,
        ...(env.CODEX_OAUTH_ID_TOKEN ? { id_token: env.CODEX_OAUTH_ID_TOKEN } : {}),
        ...(env.CODEX_OAUTH_ACCOUNT_ID ? { account_id: env.CODEX_OAUTH_ACCOUNT_ID } : {}),
      },
    });
  }

  const runtime = Object.prototype.hasOwnProperty.call(options, 'runtime') ? options.runtime : process.env.EVE_RUNTIME;
  if (runtime === 'k8s') return null;
  const home = options.home ?? (process.env.HOME || os.homedir());
  for (const dir of ['.codex', '.code']) {
    try {
      const content = await fs.readFile(path.join(home, dir, 'auth.json'), 'utf-8');
      const data = JSON.parse(content) as { tokens?: { access_token?: string }; OPENAI_API_KEY?: string };
      if (data.tokens?.access_token || data.OPENAI_API_KEY) return content;
    } catch {
      // missing or invalid: try the next
    }
  }
  return null;
}
