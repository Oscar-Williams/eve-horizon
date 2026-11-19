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

  /**
   * Whether the caller holds `permission`, on `resource` when the route names
   * one. A route on org files, docs or cloud-fs that names no resource is
   * judged, under a non-legacy org profile, on what it reaches (P1-6):
   * `reach`, when the route can name the resource it acts on (a KV path, a
   * share's path), else the org's whole data of that kind. A route that
   * filters its results to what the caller reaches says `reach: 'filtered'`
   * (see filterToReach). `strict` refuses what the caller does not reach,
   * `audit` records it (access.org_data_route_scope), `legacy` does not look.
   */
  async can(params: {
    org_id: string;
    permission: string;
    user?: AuthUser;
    project_id?: string;
    resource?: ScopedResourceContext;
    reach?: ScopedResourceContext | 'filtered';
  }): Promise<boolean> {
    const allowed = await this.canAsNamed(params);
    const { user, permission } = params;
    if (!allowed || params.resource || params.reach === 'filtered' || !isOrgDataPermission(permission)) {
      return allowed;
    }
    if (!user || user.is_admin || !this.security || !this.authService.isEnabled()) {
      return allowed;
    }
    const scope = this.orgDataScope(params.org_id, user);
    if ((await this.security.effectiveProfile(scope, 'org')) === 'legacy') {
      return allowed;
    }
    const resource = params.reach ?? wholeOrgData(permission);
    if (await this.canAsNamed({ ...params, resource })) {
      return true;
    }
    const profile = await this.security.decide(ORG_DATA_ROUTE_SCOPE_RULE, {
      ...scope,
      governing: 'org',
      actor: user,
      detail: { permission, resource: `${resource.type}:${resource.id}` },
    });
    return profile !== 'strict';
  }

  /** {@link can} for exactly the resource named (or none). */
  private async canAsNamed(params: {
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
    reach?: ScopedResourceContext | 'filtered';
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
   * What the caller reaches of one kind of org data, as a test on a resource
   * (the strict view: a built-in role's wildcard over org data is withheld).
   * A person or service principal reaches it through their grants, a job
   * token through its declared scope. `everything`: the caller is not held
   * (a system admin, a token with no scope, which assert judges, or no
   * authentication).
   */
  async reachOf(params: { org_id: string; user?: AuthUser; permission: string }): Promise<Reach> {
    const { user, permission } = params;
    if (!user || user.is_admin || !this.authService.isEnabled()) {
      return { everything: true, covers: () => true };
    }
    if (user.is_job_token) {
      if (!user.scope) return { everything: true, covers: () => true };
      return {
        everything: false,
        jobProjectId: user.project_id,
        covers: (resource) => this.tokenScopeCovers(user, permission, resource),
      };
    }
    const principal = this.resolvePrincipal(user);
    if (!principal) return { everything: true, covers: () => true };
    const covers = await this.accessService.reachPredicate({
      org_id: params.org_id,
      principal_type: principal.principal_type,
      principal_id: principal.principal_id,
      permission,
    });
    return { everything: false, covers };
  }

  /**
   * For a route that names no single resource (a list, query, search or
   * stream): hold its results to what the caller reaches, under the org's
   * profile. Each item is judged by `resourceOf` (null: not org data, kept)
   * or by `inReach`. `strict` keeps only what the caller reaches, `audit`
   * keeps everything and records what strict would hold back
   * (access.org_data_route_scope), `legacy` keeps everything. Routes that
   * filter this way call assert with `reach: 'filtered'`.
   */
  async filterToReach<T>(params: {
    org_id: string;
    user?: AuthUser;
    permission: string;
    items: T[];
    resourceOf?: (item: T) => ScopedResourceContext | null;
    inReach?: (item: T, reach: Reach) => boolean;
  }): Promise<T[]> {
    const { user, items } = params;
    if (!user || !this.security || items.length === 0) {
      return items;
    }
    const scope = this.orgDataScope(params.org_id, user);
    if ((await this.security.effectiveProfile(scope, 'org')) === 'legacy') {
      return items;
    }
    const reach = await this.reachOf(params);
    if (reach.everything) {
      return items;
    }
    const judge = params.inReach ?? ((item: T, r: Reach) => {
      const resource = params.resourceOf?.(item) ?? null;
      return !resource || r.covers(resource);
    });
    const inside = items.filter((item) => judge(item, reach));
    if (inside.length === items.length) {
      return items;
    }
    const profile = await this.security.decide(ORG_DATA_ROUTE_SCOPE_RULE, {
      ...scope,
      governing: 'org',
      actor: user,
      detail: { permission: params.permission, held_back: items.length - inside.length },
    });
    return profile === 'strict' ? inside : items;
  }

  /**
   * For a stream that names no single resource: the test each item must
   * pass, under the org's profile, or null when nothing is held back
   * (`legacy`, or a caller who reaches everything). An item outside what the
   * caller reaches is recorded (access.org_data_route_scope); `strict` drops
   * it, `audit` keeps it.
   */
  async streamReach(params: {
    org_id: string;
    user?: AuthUser;
    permission: string;
  }): Promise<((resource: ScopedResourceContext) => Promise<boolean>) | null> {
    const { user } = params;
    if (!user || !this.security) return null;
    const security = this.security;
    const scope = this.orgDataScope(params.org_id, user);
    if ((await security.effectiveProfile(scope, 'org')) === 'legacy') return null;
    const reach = await this.reachOf(params);
    if (reach.everything) return null;
    return async (resource) => {
      if (reach.covers(resource)) return true;
      const profile = await security.decide(ORG_DATA_ROUTE_SCOPE_RULE, {
        ...scope,
        governing: 'org',
        actor: user,
        detail: { permission: params.permission, stream: true },
      });
      return profile !== 'strict';
    };
  }

  /** The org whose profile governs org data for this caller: a job token's own org. */
  private orgDataScope(orgId: string, user: AuthUser): { orgId: string; projectId?: string } {
    return user.is_job_token
      ? { orgId: user.org_id ?? orgId, projectId: user.project_id }
      : { orgId };
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

/** What a caller reaches of one kind of org data (see ScopedAccessService.reachOf). */
export type Reach = {
  everything: boolean;
  covers: (resource: ScopedResourceContext) => boolean;
  /** A job token's own project. */
  jobProjectId?: string;
};

/** The org's whole data of one kind, as one resource: what a route that names none reaches. */
function wholeOrgData(permission: string): ScopedResourceContext {
  const [kind, level] = permission.split(':');
  const action = level === 'admin' ? 'admin' : level === 'write' ? 'write' : 'read';
  if (kind === 'cloud_fs') return { type: 'cloud_fs', id: '*', action };
  return { type: kind === 'orgfs' ? 'orgfs' : 'orgdocs', id: '/', action };
}
