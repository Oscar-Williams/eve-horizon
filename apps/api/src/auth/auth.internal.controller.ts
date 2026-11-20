import {
  Controller,
  Get,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  NotFoundException,
  Inject,
  Optional,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import * as yaml from 'yaml';
import {
  DEFAULT_SERVICE_PERMISSIONS,
  MEMBER_OPERATOR_PERMISSIONS,
  AccessBindingScopeSchema,
  agentSecretsAllowlist,
  getServicePermissions,
  narrowSecretsAllowlist,
  type AccessBindingScope,
  type Service,
} from '@eve/shared';
import {
  type Db,
  type Environment,
  agentQueries,
  environmentQueries,
  findJobAgent,
  jobQueries,
  projectManifestQueries,
  projectQueries,
  releaseQueries,
} from '@eve/db';
import { Public } from './auth.decorator.js';
import { InternalCallers, InternalTokenGuard } from '../common/internal-token.guard.js';
import { AuthService } from './auth.service.js';
import { AccessService } from './access.service.js';
import { OPERATOR_RIGHTS_RULE } from './rbac.service.js';
import { SecurityService } from '../security/security.service.js';
import { jobTokenPermissionsFor } from './token-scope.js';
import { AppLinkTokenMinter, type AppLinkMintRequest } from './app-link-token-minter.js';
import { isRunningAttempt } from './job-liveness.js';

@ApiTags('internal')
@Controller('internal/auth')
@UseGuards(InternalTokenGuard)
export class AuthInternalController {
  private jobs: ReturnType<typeof jobQueries>;
  private projects: ReturnType<typeof projectQueries>;
  private environments: ReturnType<typeof environmentQueries>;
  private releases: ReturnType<typeof releaseQueries>;
  private manifests: ReturnType<typeof projectManifestQueries>;
  private appLinkMinter: AppLinkTokenMinter;

  constructor(
    private readonly authService: AuthService,
    @Inject('DB') private readonly db: Db,
    private readonly accessService: AccessService,
    @Optional() private readonly security?: SecurityService,
  ) {
    this.jobs = jobQueries(db);
    this.projects = projectQueries(db);
    this.environments = environmentQueries(db);
    this.releases = releaseQueries(db);
    this.manifests = projectManifestQueries(db);
    this.appLinkMinter = new AppLinkTokenMinter(authService, db);
  }

  @Public()
  @Post('mint-job-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Mint a job token with explicit permissions for agent CLI access (internal only)' })
  async mintJobToken(
    @Body() body: { job_id: string; permissions?: string[]; scopes?: string[]; scope?: unknown; ttl_seconds?: number; attempt_id?: string },
  ): Promise<{ access_token: string; token_type: string; expires_at: number }> {
    const job = await this.jobs.findById(body.job_id);
    if (!job) {
      throw new NotFoundException(`Job ${body.job_id} not found`);
    }

    const project = await this.projects.findById(job.project_id);
    if (!project) {
      throw new NotFoundException(`Project ${job.project_id} not found`);
    }

    // Accept both 'permissions' (new) and 'scopes' (legacy) in request body
    const permissions = await jobTokenPermissionsFor(
      this.accessService,
      job.actor_user_id,
      project.org_id,
      job.project_id,
      body.permissions ?? body.scopes ?? [],
      { userSecretsExcluded: job.user_secrets_excluded },
    );
    let scope: AccessBindingScope | undefined;
    if (body.scope !== undefined) {
      const parsedScope = AccessBindingScopeSchema.safeParse(body.scope);
      if (!parsedScope.success) {
        throw new UnauthorizedException('Invalid job token scope');
      }
      scope = parsedScope.data;
    }

    const agentSlug = (job.target as { agent_slug?: string } | null)?.agent_slug;

    // A token bound to the running attempt stops working when that attempt ends.
    if (body.attempt_id && !await isRunningAttempt(this.jobs, job.id, body.attempt_id)) {
      throw new UnauthorizedException(`Attempt ${body.attempt_id} is not job ${job.id}'s running attempt`);
    }

    // The job's effective secrets allowlist rides on its token, so work the
    // job starts or changes cannot receive secrets the job itself may not.
    const agent = await findJobAgent(agentQueries(this.db), {
      projectId: job.project_id,
      agentId: job.assignee,
      agentSlug: (job.target as { agent_slug?: string } | null)?.agent_slug,
    }, project.org_id);
    const secretsAllowlist = narrowSecretsAllowlist(agentSecretsAllowlist(agent?.access_json), job.secrets_allowlist ?? null);

    const accessToken = this.authService.mintJobToken({
      userId: job.actor_user_id ?? 'system',
      orgId: project.org_id,
      projectId: job.project_id,
      jobId: job.id,
      permissions: await this.withoutDefaultOperatorRights(permissions, [
        ...declaredPermissions(agent?.access_json),
        ...(job.token_permissions ?? []),
      ], { projectId: job.project_id, orgId: project.org_id }),
      scope,
      ttlSeconds: body.ttl_seconds,
      agentSlug: agentSlug ?? undefined,
      userSecretsExcluded: job.user_secrets_excluded,
      secretsAllowlist,
      ...(body.attempt_id ? { attemptId: body.attempt_id } : {}),
    });

    // Decode the exp claim for the response
    const parts = accessToken.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_at: payload.exp,
    };
  }

  /**
   * Rule access.operator_rights: under a strict project the default job
   * permissions do not carry the member role's operator permissions
   * (jobs:harness_override). A job token keeps one only when the job's agent
   * (access.permissions) or the job's own token permissions declare it.
   */
  private async withoutDefaultOperatorRights(
    permissions: string[],
    declared: readonly string[],
    scope: { projectId: string; orgId: string },
  ): Promise<string[]> {
    const undeclared = new Set<string>(MEMBER_OPERATOR_PERMISSIONS.filter((p) => permissions.includes(p) && !declared.includes(p)));
    if (undeclared.size === 0 || !this.security) return permissions;
    const profile = await this.security.effectiveProfile(scope, 'project', OPERATOR_RIGHTS_RULE);
    return profile === 'strict' ? permissions.filter((p) => !undeclared.has(p)) : permissions;
  }

  @Public()
  @Post('magic-link-wrap/inspect')
  @InternalCallers('sso')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Inspect a magic-link wrap (read-only with telemetry bump)',
    description:
      'Returns the metadata needed to render the SSO confirmation interstitial: kind, project_id, org_id, redirect_to, expiry/consumed flags, and the running get_count so scanner pre-fetches are visible. Increments get_count and last_get_at on every call — used by both HEAD and GET handlers on the SSO. Never reveals the underlying GoTrue action_link.',
  })
  async inspectMagicLinkWrap(
    @Body() body: { wrap_token?: string },
  ): Promise<
    | {
        found: true;
        kind: 'magic_link' | 'invite';
        project_id: string | null;
        org_id: string | null;
        redirect_to: string | null;
        expires_at: string;
        expired: boolean;
        consumed: boolean;
        get_count: number;
      }
    | { found: false }
  > {
    const id = (body.wrap_token ?? '').trim();
    if (!id) {
      return { found: false };
    }
    const inspected = await this.authService.inspectMagicLinkWrap(id);
    if (!inspected.found) {
      return { found: false };
    }
    return {
      found: true,
      kind: inspected.kind,
      project_id: inspected.project_id,
      org_id: inspected.org_id,
      redirect_to: inspected.redirect_to,
      expires_at: inspected.expires_at.toISOString(),
      expired: inspected.expired,
      consumed: inspected.consumed,
      get_count: inspected.get_count,
    };
  }

  @Public()
  @Post('magic-link-wrap/consume')
  @InternalCallers('sso')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Consume a magic-link wrap and reveal the GoTrue action_link',
    description:
      'Atomically marks the wrap consumed. On success returns the stored GoTrue action_link (the SSO 302-redirects the browser there). On failure returns {status: expired | already_consumed | unknown} so the SSO can render the right "can\'t be used" page.',
  })
  async consumeMagicLinkWrap(
    @Body() body: { wrap_token?: string },
  ): Promise<
    | { status: 'ok'; gotrue_action_link: string; kind: 'magic_link' | 'invite'; project_id: string | null; org_id: string | null }
    | { status: 'expired' | 'already_consumed' | 'unknown' }
  > {
    const id = (body.wrap_token ?? '').trim();
    if (!id) {
      return { status: 'unknown' };
    }
    const result = await this.authService.consumeMagicLinkWrap(id);
    if (result.status !== 'ok') {
      return { status: result.status };
    }
    return {
      status: 'ok',
      gotrue_action_link: result.gotrue_action_link,
      kind: result.kind,
      project_id: result.project_id,
      org_id: result.org_id,
    };
  }

  /**
   * A service token grants at most DEFAULT_SERVICE_PERMISSIONS plus the
   * service's `x-eve.permissions` in the manifest of the release deployed to
   * the env (the one being deployed, when the worker names it, else the
   * env's current release). Anything else requested is left out. The env
   * must exist in the project, and the project in the org.
   */
  @Public()
  @Post('mint-service-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Mint a service token for deployed app services (internal only)' })
  async mintServiceToken(
    @Body() body: {
      project_id: string;
      org_id: string;
      env_name: string;
      service_name: string;
      permissions?: string[];
      ttl_seconds?: number;
      /** The release being deployed, whose manifest declares the service's permissions. */
      release_id?: string;
    },
  ): Promise<{ access_token: string; token_type: string; expires_at: number }> {
    const project = await this.projects.findById(body.project_id);
    if (!project || project.org_id !== body.org_id) {
      throw new NotFoundException(`Project ${body.project_id} not found in org ${body.org_id}`);
    }
    const environment = await this.environments.findByProjectAndName(project.id, body.env_name);
    if (!environment) {
      throw new NotFoundException(`Environment ${body.env_name} not found in project ${project.id}`);
    }

    const allowed = new Set<string>([
      ...DEFAULT_SERVICE_PERMISSIONS,
      ...await this.declaredServicePermissions(project.id, environment, body.release_id, body.service_name),
    ]);
    const requested = body.permissions ?? [...DEFAULT_SERVICE_PERMISSIONS];
    const permissions = [...new Set(requested.filter((permission) => allowed.has(permission)))];

    const accessToken = this.authService.mintServiceToken({
      projectId: project.id,
      orgId: body.org_id,
      envName: body.env_name,
      serviceName: body.service_name,
      permissions,
      ttlSeconds: body.ttl_seconds,
    });

    const parts = accessToken.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());

    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_at: payload.exp,
    };
  }

  /** The service's `x-eve.permissions` in the manifest of the env's release; none when there is none. */
  private async declaredServicePermissions(
    projectId: string,
    environment: Pick<Environment, 'current_release_id' | 'last_applied_release_id'>,
    releaseId: string | undefined,
    serviceName: string,
  ): Promise<string[]> {
    const id = releaseId ?? environment.current_release_id ?? environment.last_applied_release_id;
    if (!id) return [];
    const release = await this.releases.findById(id);
    if (!release || release.project_id !== projectId) {
      if (releaseId) throw new NotFoundException(`Release ${releaseId} not found in project ${projectId}`);
      return [];
    }
    const manifest = await this.manifests.findByProjectAndHash(projectId, release.manifest_hash);
    if (!manifest) return [];
    let parsed: { services?: Record<string, unknown> } | null;
    try {
      parsed = yaml.parse(manifest.manifest_yaml) as { services?: Record<string, unknown> } | null;
    } catch {
      return [];
    }
    const service = parsed?.services?.[serviceName];
    return service && typeof service === 'object' ? getServicePermissions(service as Service) : [];
  }

  /** The key the API signs tokens with now, for the worker's service-token renewal. */
  @Public()
  @Get('signing-key')
  @ApiOperation({ summary: 'The key the API signs tokens with now (internal only)' })
  signingKey(): { kid: string; public_key: Record<string, unknown> } {
    return this.authService.getSigningKey();
  }

  @Public()
  @Post('mint-app-link-token')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Mint an app-link token for cross-project API access (internal only)' })
  async mintAppLinkToken(
    @Body() body: AppLinkMintRequest,
  ): Promise<{ access_token: string; token_type: string; expires_at: number }> {
    return this.appLinkMinter.mint(body);
  }
}

/** The permissions an agent declares in `access.permissions`. */
function declaredPermissions(access: Record<string, unknown> | null | undefined): string[] {
  const raw = access?.permissions;
  return Array.isArray(raw) ? raw.filter((p): p is string => typeof p === 'string') : [];
}
