import {
  Controller,
  Post,
  Body,
  HttpCode,
  HttpStatus,
  UnauthorizedException,
  NotFoundException,
  Inject,
  UseGuards,
} from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import { DEFAULT_SERVICE_PERMISSIONS, AccessBindingScopeSchema, agentSecretsAllowlist, narrowSecretsAllowlist, type AccessBindingScope } from '@eve/shared';
import { type Db, agentQueries, findJobAgent, jobQueries, projectQueries } from '@eve/db';
import { Public } from './auth.decorator.js';
import { InternalTokenGuard } from '../common/internal-token.guard.js';
import { AuthService } from './auth.service.js';
import { AccessService } from './access.service.js';
import { jobTokenPermissionsFor } from './token-scope.js';
import { AppLinkTokenMinter, type AppLinkMintRequest } from './app-link-token-minter.js';
import { isRunningAttempt } from './job-liveness.js';

@ApiTags('internal')
@Controller('internal/auth')
@UseGuards(InternalTokenGuard)
export class AuthInternalController {
  private jobs: ReturnType<typeof jobQueries>;
  private projects: ReturnType<typeof projectQueries>;
  private appLinkMinter: AppLinkTokenMinter;

  constructor(
    private readonly authService: AuthService,
    @Inject('DB') private readonly db: Db,
    private readonly accessService: AccessService,
  ) {
    this.jobs = jobQueries(db);
    this.projects = projectQueries(db);
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
      permissions,
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

  @Public()
  @Post('magic-link-wrap/inspect')
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
    },
  ): Promise<{ access_token: string; token_type: string; expires_at: number }> {
    const accessToken = this.authService.mintServiceToken({
      projectId: body.project_id,
      orgId: body.org_id,
      envName: body.env_name,
      serviceName: body.service_name,
      permissions: body.permissions ?? [...DEFAULT_SERVICE_PERMISSIONS],
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
