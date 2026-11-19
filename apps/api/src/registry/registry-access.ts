import { createHash, timingSafeEqual } from 'crypto';
import {
  eveRegistryRepositoryPrefix,
  verifyRegistryPullCredential,
  verifyRegistryPushCredential,
} from '@eve/shared';

export interface RegistryAccessEntry {
  type: string;
  name: string;
  actions: string[];
}

/**
 * Who is asking the token endpoint for registry access.
 *
 * - `internal`: holds an internal key (the internal POST endpoint, or the
 *   legacy `EVE_INTERNAL_API_KEY` as a Basic password). May push and pull
 *   anywhere.
 * - `project-push`: presents a build's push credential (BuildKit or Kaniko).
 *   May push and pull under the project's repository prefix, until it expires.
 * - `project-pull`: presents an environment's pull credential from an app
 *   namespace's `eve-registry` pull secret (kubelet). May pull under the
 *   project's repository prefix, while the credential is current
 *   (`isPullCredentialCurrent`).
 */
export type RegistryCaller =
  | { kind: 'internal' }
  | { kind: 'project-push'; projectId: string; expiresAt: number }
  | { kind: 'project-pull'; projectId: string; environmentId: string; namespace: string; epoch: number };

/** The environment fields a pull credential is checked against. */
export interface PullCredentialEnvironment {
  project_id: string;
  status: string;
  registry_pull_epoch: number;
}

/**
 * A pull credential is honoured only while its environment still exists,
 * belongs to the credential's (non-deleted) project, is not terminated, and is
 * at the pull epoch the credential was minted for, or the one before it. The
 * one-epoch grace covers kubelet's short-lived secret cache and a deploy and a
 * job run rewriting the secret at the same time; the credential written two
 * rewrites ago is refused.
 */
export function isPullCredentialCurrent(
  caller: Extract<RegistryCaller, { kind: 'project-pull' }>,
  environment: PullCredentialEnvironment | null,
  projectIsLive: boolean,
): boolean {
  if (!environment || !projectIsLive) return false;
  if (environment.project_id !== caller.projectId) return false;
  if (environment.status === 'terminated') return false;
  const current = environment.registry_pull_epoch;
  return caller.epoch === current || caller.epoch === current - 1;
}

const GRANTABLE_ACTIONS: Record<RegistryCaller['kind'], ReadonlySet<string>> = {
  internal: new Set(['pull', 'push']),
  'project-push': new Set(['pull', 'push']),
  'project-pull': new Set(['pull']),
};

function secretsEqual(presented: string, expected: string): boolean {
  const digest = (value: string) => createHash('sha256').update(value, 'utf8').digest();
  return timingSafeEqual(digest(presented), digest(expected));
}

/** The keys the token endpoint checks a Basic-auth password against. */
export interface RegistryVerificationKeys {
  /** `EVE_REGISTRY_CREDENTIAL_KEY`: signs credentials from 0.1.327 on. */
  credentialKey?: string;
  /** The legacy `EVE_INTERNAL_API_KEY`: the password itself, or the key older credentials were signed with. */
  internalKey?: string;
}

/**
 * Identify a Basic-auth password as the internal key, a push credential or
 * a pull credential, and say which key proved it: `credential` for the
 * registry credential key, `internal` for the internal key itself or a
 * credential signed with it (which `registry.internal_key` governs).
 */
export function identifyRegistryCaller(
  password: string | undefined,
  keys: RegistryVerificationKeys,
): { caller: RegistryCaller; key: 'credential' | 'internal' } | null {
  if (!password) return null;
  if (keys.internalKey && secretsEqual(password, keys.internalKey)) {
    return { caller: { kind: 'internal' }, key: 'internal' };
  }
  const signers: Array<['credential' | 'internal', string | undefined]> = [
    ['credential', keys.credentialKey],
    ['internal', keys.internalKey],
  ];
  for (const [key, signingKey] of signers) {
    if (!signingKey) continue;
    const push = verifyRegistryPushCredential(password, signingKey);
    if (push) return { caller: { kind: 'project-push', ...push }, key };
    const pull = verifyRegistryPullCredential(password, signingKey);
    if (pull) return { caller: { kind: 'project-pull', ...pull }, key };
  }
  return null;
}

function projectPrefix(caller: RegistryCaller): string | null {
  if (caller.kind === 'internal') return null;
  try {
    return eveRegistryRepositoryPrefix(caller.projectId);
  } catch {
    return '';
  }
}

/**
 * Reduce the requested scopes to what the caller may hold, following the
 * Docker token spec (grant the permitted subset, never fail the request):
 *
 * - only `repository` resources (no `registry:catalog`);
 * - `pull`/`push` for internal and push callers, `pull` for pull callers
 *   (never `delete` or `*`);
 * - project callers only on repositories under their project's prefix
 *   (`<project id>/`), which the platform assigns, not the manifest.
 *
 * Entries left with no actions are dropped.
 */
export function grantRegistryAccess(
  caller: RegistryCaller,
  requested: RegistryAccessEntry[],
): RegistryAccessEntry[] {
  const grantable = GRANTABLE_ACTIONS[caller.kind];
  const prefix = projectPrefix(caller);
  if (prefix === '') return [];
  const granted: RegistryAccessEntry[] = [];
  for (const entry of requested) {
    if (entry.type !== 'repository') continue;
    if (prefix !== null && !entry.name.startsWith(prefix)) continue;
    const actions = [...new Set(entry.actions.filter((action) => grantable.has(action)))];
    if (actions.length > 0) {
      granted.push({ type: 'repository', name: entry.name, actions });
    }
  }
  return granted;
}
