/**
 * Secrets allowlists: which secrets an agent job receives.
 *
 * By default a job receives every secret it can resolve (system, org, user and
 * project scope). An agent (`access.secrets` in agents.yaml) or a workflow
 * agent step (`secrets:`) can declare an allowlist; the job then receives only
 * the secrets named there, as env vars or files, whatever scope they come from.
 *
 * `null` means "not declared" (no restriction). An empty list means "no
 * secrets". When several allowlists apply, a job receives only the keys every
 * one of them names.
 */

import type { SecretResolveItem } from '../schemas/secret.js';

/** The narrowest of the declared allowlists: keys every declared list names. */
export function narrowSecretsAllowlist(
  ...lists: Array<readonly string[] | null | undefined>
): string[] | null {
  const declared = lists.filter((list): list is readonly string[] => Array.isArray(list));
  if (declared.length === 0) return null;
  const [first, ...others] = declared;
  const kept = new Set(first.filter((key) => others.every((list) => list.includes(key))));
  return [...kept].sort();
}

/** Keep only the allowlisted secrets; every secret when nothing is declared. */
export function filterSecretsByAllowlist(
  secrets: SecretResolveItem[],
  allowlist: readonly string[] | null | undefined,
): SecretResolveItem[] {
  if (!allowlist) return secrets;
  const allowed = new Set(allowlist);
  return secrets.filter((secret) => allowed.has(secret.key));
}

/**
 * The allowlist an agent declares in `access.secrets`, read from the agent's
 * stored access config. A stored value that is not a list of names fails
 * closed (no secrets) rather than open.
 */
export function agentSecretsAllowlist(access: Record<string, unknown> | null | undefined): string[] | null {
  if (!access || !Object.prototype.hasOwnProperty.call(access, 'secrets')) return null;
  const raw = access.secrets;
  if (raw === undefined || raw === null) return null;
  if (!Array.isArray(raw)) return [];
  return raw.filter((key): key is string => typeof key === 'string' && key.length > 0);
}

type AllowlistLogger = (
  attemptId: string,
  phase: string,
  action: 'start' | 'end' | 'log',
  meta?: Record<string, unknown>,
) => Promise<void>;

/**
 * The secrets a job receives, given every secret resolved for it and the
 * invocation's allowlist. When an allowlist applies, records which names it
 * kept and how many it withheld (names and counts only, never values).
 */
export async function selectJobSecrets(
  invocation: { attemptId?: string; secrets_allowlist?: string[] },
  resolved: SecretResolveItem[],
  logLifecycle?: AllowlistLogger,
): Promise<SecretResolveItem[]> {
  const allowlist = invocation.secrets_allowlist;
  // A clone-only credential is the platform's, for the workspace clone: never the job's.
  const kept = filterSecretsByAllowlist(resolved.filter((secret) => !secret.clone_only), allowlist);
  if (allowlist && invocation.attemptId && logLifecycle) {
    const present = new Set(kept.map((secret) => secret.key));
    await logLifecycle(invocation.attemptId, 'secrets', 'log', {
      kind: 'secrets_allowlist',
      allowlist,
      received: [...present].sort(),
      missing: allowlist.filter((key) => !present.has(key)),
      withheld_count: resolved.length - kept.length,
    });
  }
  return kept;
}
