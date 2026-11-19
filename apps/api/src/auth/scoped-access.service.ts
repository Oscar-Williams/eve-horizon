import { Injectable, UnauthorizedException } from '@nestjs/common';
import { hasUserActor } from '@eve/shared';
import type { AuthUser } from './auth.service.js';
import { AuthService } from './auth.service.js';
import { AccessService, isOrgDataPermission, ORG_DATA_NO_USER_RULE, ORG_DATA_UNSCOPED_RULE } from './access.service.js';
import { RbacService } from './rbac.service.js';
import { tokenMayAddressOrg, tokenMayAddressProject } from './token-scope.js';
import { buildApiError } from '../system/api-errors.js';
import { SecurityService } from '../security/security.service.js';

export { ORG_DATA_UNSCOPED_RULE, ORG_DATA_NO_USER_RULE };
/** A route that names no resource reached org data outside what the caller's grants or scope reach (P1-6). */
export const ORG_DATA_ROUTE_SCOPE_RULE = 'access.org_data_route_scope';

export type ScopedResourceContext = {
  type: 'orgfs' | 'orgdocs' | 'envdb' | 'cloud_fs';
  id: string;
  action: 'read' | 'write' | 'admin';
};

type AccessPrincipal = {
  principal_type: 'user' | 'service_principal';
  principal_id: string;
};

@Injectable()
export class ScopedAccessService {
  constructor(
    private readonly authService: AuthService,
    private readonly accessService: AccessService,
    private readonly rbacService: RbacService,
    private readonly security?: SecurityService,
  ) {}

  async can(params: {
    org_id: string;
    permission: string;
    user?: AuthUser;
    project_id?: string;
    resource?: ScopedResourceContext;
  }): Promise<boolean> {
    // Job tokens carry explicit permissions — check those directly
    // rather than going through access groups (job principals aren't org members).
    // They hold them only inside the org and project they were minted for.
    if (params.user?.is_job_token && params.user.permissions) {
      if (!params.user.permissions.includes(params.permission)) {
        return false;
      }
      if (!(await this.jobTokenMayAddress(params.user, params.org_id, params.project_id))) {
        return false;
      }
      if (isOrgDataPermission(params.permission) && !(await this.jobMayUseOrgData(params.user, params.permission))) {
        return false;
      }
      if (!params.user.scope) {
        return true;
      }
      const scopeEval = this.accessService.evaluateScope(
        params.user.scope,
        params.permission,
        params.resource,
      );
      return !scopeEval.scope_required || scopeEval.scope_matched;
    }

    const principal = this.resolvePrincipal(params.user);
    if (!principal) {
      return true;
    }

    const result = await this.accessService.can({
      org_id: params.org_id,
      principal_type: principal.principal_type,
      principal_id: principal.principal_id,
      project_id: params.project_id,
      permission: params.permission,
      resource: params.resource,
    });

    return result.allowed;
  }

  async assert(params: {
    org_id: string;
    permission: string;
    user?: AuthUser;
    project_id?: string;
    resource?: ScopedResourceContext;
    request_id?: string;
  }): Promise<void> {
    const allowed = await this.can(params);
    if (allowed) {
      return;
    }

    throw buildApiError(
      403,
      'resource_access_denied',
      params.resource
        ? `Access denied for resource: ${params.resource.type}:${params.resource.id}`
        : `Access denied for permission: ${params.permission}`,
      {
        requestId: params.request_id,
        details: {
          permission: params.permission,
          resource: params.resource ?? null,
        },
      },
    );
  }

  /**
   * For a route that reaches org data without naming one resource (listing
   * cloud-fs mounts, reading the default mount): hold a job token to the org
   * data rules alone. Other callers, and other permissions, pass.
   */
  async assertJobMayUseOrgData(params: {
    org_id: string;
    permission: string;
    user?: AuthUser;
    request_id?: string;
  }): Promise<void> {
    const { user, permission } = params;
    if (!user?.is_job_token || !isOrgDataPermission(permission) || (await this.jobMayUseOrgData(user, permission))) {
      return;
    }
    throw buildApiError(403, 'resource_access_denied', `Access denied for permission: ${permission}`, {
      requestId: params.request_id,
      details: { permission, resource: null },
    });
  }

  /**
   * The cloud-fs mounts a route that names no mount (listing, default-mount
   * reads) may show this caller, under the org's profile. `legacy` keeps
   * today's view: every mount, or the mounts a job token's scope lists.
   * Otherwise each mount must be one the caller reaches: a person or service
   * principal through their grants, a job token through its scope. `audit`
   * keeps today's view and records when some mount would be held back;
   * `strict` holds them back.
   */
  async readableMounts<T extends { id: string }>(params: { org_id: string; user?: AuthUser; mounts: T[] }): Promise<T[]> {
    const { org_id, user, mounts } = params;
    const listed = mountsInTokenScope(mounts, user);
    if (!this.security || !user || user.is_admin || listed.length === 0) {
      return listed;
    }
    const scope = { orgId: user.is_job_token ? user.org_id ?? org_id : org_id, projectId: user.is_job_token ? user.project_id : undefined };
    if ((await this.security.effectiveProfile(scope, 'org')) === 'legacy') {
      return listed;
    }
    const reachable: T[] = [];
    for (const mount of listed) {
      if (await this.mountReachable(org_id, user, mount.id)) reachable.push(mount);
    }
    if (reachable.length === listed.length) {
      return listed;
    }
    const profile = await this.security.decide(ORG_DATA_ROUTE_SCOPE_RULE, {
      ...scope,
      governing: 'org',
      actor: user,
      detail: { permission: 'cloud_fs:read', held_back: listed.length - reachable.length },
    });
    return profile === 'strict' ? reachable : listed;
  }

  /** Whether the caller reaches this mount, judged as a route naming it would judge it. */
  private async mountReachable(orgId: string, user: AuthUser, mountId: string): Promise<boolean> {
    if (user.is_job_token) {
      // A scoped token reaches a mount only through its cloud_fs entry; a
      // token with no scope was judged before (assertJobMayUseOrgData).
      if (!user.scope) return true;
      const allowed = user.scope.cloud_fs?.allow_mount_ids ?? [];
      return allowed.includes('*') || allowed.includes(mountId);
    }
    return this.can({
      org_id: orgId,
      permission: 'cloud_fs:read',
      user,
      resource: { type: 'cloud_fs', id: mountId, action: 'read' },
    });
  }

  /** Whether a job token's declared scope covers this resource (a token with no scope: yes). */
  tokenScopeCovers(user: AuthUser, permission: string, resource: ScopedResourceContext): boolean {
    if (!user.scope) return true;
    const evaluation = this.accessService.evaluateScope(user.scope, permission, resource);
    return !evaluation.scope_required || evaluation.scope_matched;
  }

  /**
   * For a route that names no single resource (a search or a listing): hold
   * a job token's results to its declared scope, under the org's profile.
   * `strict` keeps only the items `inScope` accepts, `audit` keeps them all
   * and records what strict would hold back (access.org_data_route_scope),
   * `legacy` keeps them all. Other callers, and a token with no scope (judged
   * by assert), get the items as they are.
   */
  async filterToJobScope<T>(params: {
    org_id: string;
    user?: AuthUser;
    permission: string;
    items: T[];
    inScope: (item: T) => boolean;
  }): Promise<T[]> {
    const { user, items } = params;
    if (!user?.is_job_token || !user.scope || !this.security || items.length === 0) {
      return items;
    }
    const inside = items.filter(params.inScope);
    if (inside.length === items.length) {
      return items;
    }
    const profile = await this.security.decide(ORG_DATA_ROUTE_SCOPE_RULE, {
      governing: 'org',
      orgId: user.org_id ?? params.org_id,
      projectId: user.project_id,
      actor: user,
      detail: { permission: params.permission, held_back: items.length - inside.length },
    });
    return profile === 'strict' ? inside : items;
  }

  /**
   * For a route on org data whose results cannot be filtered (agent KV,
   * thread distillation, org-fs device enrolment): a job token with a
   * declared scope needs the resource inside it. Under the org's profile,
   * `strict` refuses (403) a resource outside it, or a route that names
   * none; `audit` records it (access.org_data_route_scope); `legacy` does not
   * look. Other callers pass.
   */
  async assertJobRouteInScope(params: {
    org_id: string;
    user?: AuthUser;
    permission: string;
    resource?: ScopedResourceContext;
    request_id?: string;
  }): Promise<void> {
    const { user, permission, resource } = params;
    if (!user?.is_job_token || !user.scope || !this.security) return;
    if (resource && this.tokenScopeCovers(user, permission, resource)) return;
    const profile = await this.security.decide(ORG_DATA_ROUTE_SCOPE_RULE, {
      governing: 'org',
      orgId: user.org_id ?? params.org_id,
      projectId: user.project_id,
      actor: user,
      detail: { permission, resource: resource ? `${resource.type}:${resource.id}` : 'none' },
    });
    if (profile === 'strict') {
      throw buildApiError(403, 'resource_access_denied', resource
        ? `Access denied for resource: ${resource.type}:${resource.id}`
        : `Access denied for permission: ${permission}`, {
        requestId: params.request_id,
        details: { permission, resource: resource ?? null },
      });
    }
  }

  /**
   * Org files, docs and cloud-fs belong to the org, whose profile decides
   * whether a job reaches them without a scope or without a user who started
   * the work: `strict` refuses, `audit` records, `legacy` allows. The token
   * may only address its own org (checked before this), so that org governs.
   */
  private async jobMayUseOrgData(user: AuthUser, permission: string): Promise<boolean> {
    const rule = !hasUserActor(user.user_id)
      ? ORG_DATA_NO_USER_RULE
      : !user.scope
        ? ORG_DATA_UNSCOPED_RULE
        : null;
    if (!rule || !this.security) {
      return true;
    }
    const profile = await this.security.decide(rule, {
      governing: 'org',
      orgId: user.org_id,
      projectId: user.project_id,
      actor: user,
      detail: { permission },
    });
    return profile !== 'strict';
  }

  /** A lookup that fails (unknown or ambiguous org or project) counts as outside the token's scope. */
  private async jobTokenMayAddress(user: AuthUser, orgId: string, projectId?: string): Promise<boolean> {
    try {
      return (await tokenMayAddressOrg(user, orgId, this.rbacService))
        && (!projectId || (await tokenMayAddressProject(user, projectId, this.rbacService)));
    } catch {
      return false;
    }
  }

  private resolvePrincipal(user?: AuthUser): AccessPrincipal | null {
    if (!this.authService.isEnabled()) {
      return null;
    }

    if (!user?.user_id) {
      throw new UnauthorizedException('Missing user context');
    }

    return {
      principal_type: user.is_service_principal ? 'service_principal' : 'user',
      principal_id: user.user_id,
    };
  }
}

/**
 * The mounts a job token's scope lists (all of them for `*`, or for a token
 * with no cloud-fs entry); every mount for any other caller.
 */
export function mountsInTokenScope<T extends { id: string }>(mounts: T[], user?: AuthUser): T[] {
  const allowed = user?.scope?.cloud_fs?.allow_mount_ids;
  if (!user?.is_job_token || !user.scope || !allowed || allowed.includes('*')) return mounts;
  const allowedSet = new Set(allowed);
  return mounts.filter((mount) => allowedSet.has(mount.id));
}
