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
    await updateSecret(scopeType, scopeId, 'CODEX_AUTH_JSON_B64', newB64);
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
  invocation: { secrets_allowlist?: string[] },
): string[] {
  if (invocation.secrets_allowlist || !configDir) return [];
  return [path.join(configDir, 'auth.json')];
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
