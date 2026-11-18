import { Injectable, UnauthorizedException } from '@nestjs/common';
import { hasUserActor } from '@eve/shared';
import type { AuthUser } from './auth.service.js';
import { AuthService } from './auth.service.js';
import { AccessService, isOrgDataPermission } from './access.service.js';
import { RbacService } from './rbac.service.js';
import { tokenMayAddressOrg, tokenMayAddressProject } from './token-scope.js';
import { buildApiError } from '../system/api-errors.js';
import { SecurityService } from '../security/security.service.js';

/** A job token with no `scope` used org files, docs or cloud-fs (P1-6). */
export const ORG_DATA_UNSCOPED_RULE = 'access.org_data_unscoped';
/** A job token for work no user started used org files, docs or cloud-fs (P1-6). */
export const ORG_DATA_NO_USER_RULE = 'access.org_data_no_user';

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
