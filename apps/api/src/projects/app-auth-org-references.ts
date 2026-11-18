import { ForbiddenException } from '@nestjs/common';
import type { ProjectAuthConfig } from '@eve/shared';
import type { AuthUser } from '../auth/auth.types.js';
import { isScopedToken } from '../auth/token-scope.js';

const ORG_ADMIN_ROLES = new Set(['owner', 'admin']);

type DomainSignupRuleLike = { domain?: unknown; target_org?: unknown };

/** Org access as stored on the project: canonical org ids, possibly malformed. */
type StoredOrgAccess = {
  allowed_orgs?: unknown;
  domain_signup?: { enabled?: unknown; domains?: unknown };
};

function storedOrgAccess(previous: unknown): StoredOrgAccess {
  if (!previous || typeof previous !== 'object') return {};
  const orgAccess = (previous as { org_access?: unknown }).org_access;
  return orgAccess && typeof orgAccess === 'object' ? (orgAccess as StoredOrgAccess) : {};
}

function ruleKey(rule: DomainSignupRuleLike): string {
  return `${String(rule.domain)}\u0000${String(rule.target_org)}`;
}

/**
 * The orgs a newly synced app sign-in config reaches that the stored config
 * did not: each allowed org other than the project's own, and each domain
 * sign-up rule's target org. A sign-up rule adds people to its target org, so
 * it counts even when that org is the project's own.
 */
export function newAuthOrgReferences(
  projectOrgId: string,
  previous: unknown,
  next: ProjectAuthConfig | null,
): string[] {
  if (!next) return [];

  const before = storedOrgAccess(previous);
  const allowedBefore = new Set(Array.isArray(before.allowed_orgs) ? before.allowed_orgs : []);
  const rulesBefore = new Set(
    before.domain_signup?.enabled === true && Array.isArray(before.domain_signup.domains)
      ? (before.domain_signup.domains as DomainSignupRuleLike[]).map(ruleKey)
      : [],
  );

  const orgIds = new Set<string>();
  for (const orgId of next.org_access.allowed_orgs) {
    if (orgId !== projectOrgId && !allowedBefore.has(orgId)) orgIds.add(orgId);
  }
  if (next.org_access.domain_signup.enabled) {
    for (const rule of next.org_access.domain_signup.domains) {
      if (!rulesBefore.has(ruleKey(rule))) orgIds.add(rule.target_org);
    }
  }
  return [...orgIds];
}

/**
 * Refuse (403) a manifest sync that widens which orgs an app signs people
 * into, unless a person who administers every newly named org makes it. Job,
 * service and app-link tokens may only re-sync what is already stored.
 */
export async function assertMayDeclareAuthOrgReferences(params: {
  caller: AuthUser | undefined;
  projectOrgId: string;
  previous: unknown;
  next: ProjectAuthConfig | null;
  findOrgRole: (userId: string, orgId: string) => Promise<string | null>;
  /** With sign-in disabled (local development) there is no caller and the guard allows all. */
  authEnabled: boolean;
}): Promise<void> {
  const orgIds = newAuthOrgReferences(params.projectOrgId, params.previous, params.next);
  if (orgIds.length === 0) return;

  const { caller } = params;
  if (!caller && !params.authEnabled) return;
  if (!caller || isScopedToken(caller) || caller.is_app_link_token) {
    throw new ForbiddenException(
      'Only a person can change which orgs an app signs people into (x-eve.auth.org_access): '
      + 'an admin of each named org must run the sync once (eve project sync)',
    );
  }

  for (const orgId of orgIds) {
    if (caller.bound_org_id) {
      if (caller.bound_org_id !== orgId) {
        throw new ForbiddenException(
          `This token is limited to org ${caller.bound_org_id} and cannot add app sign-in for org ${orgId}`,
        );
      }
    } else if (caller.is_admin) {
      continue;
    }
    const role = await params.findOrgRole(caller.user_id, orgId);
    if (!role || !ORG_ADMIN_ROLES.has(role)) {
      throw new ForbiddenException(
        `Adding app sign-in for org ${orgId} (x-eve.auth.org_access) needs an admin or owner of that org`,
      );
    }
  }
}
