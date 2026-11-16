import { NotFoundException, UnauthorizedException } from '@nestjs/common';
import { type Db, appLinkSubscriptionQueries, jobQueries, projectQueries } from '@eve/db';
import type { AuthService } from './auth.service.js';
import { isRunningAttempt } from './job-liveness.js';

export interface AppLinkMintRequest {
  subscription_id: string;
  consumer_principal: string;
  consumer_env?: string | null;
  producer_env?: string | null;
  ttl_seconds?: number;
  /** Required for a non-job principal (a deployed service): its project. */
  consumer_project_id?: string | null;
  /** For a `job:<id>` principal: the running attempt to bind the token to. */
  attempt_id?: string | null;
}

export interface MintedToken {
  access_token: string;
  token_type: string;
  expires_at: number;
}

/**
 * Mints app-link tokens after checking the subscription belongs to the
 * principal's project and its grant allows the producer env. Shared by the
 * internal mint endpoint (runtimes and deploys) and the job-facing refresh.
 */
export class AppLinkTokenMinter {
  private readonly jobs: ReturnType<typeof jobQueries>;
  private readonly projects: ReturnType<typeof projectQueries>;
  private readonly appLinkSubscriptions: ReturnType<typeof appLinkSubscriptionQueries>;

  constructor(private readonly authService: AuthService, db: Db) {
    this.jobs = jobQueries(db);
    this.projects = projectQueries(db);
    this.appLinkSubscriptions = appLinkSubscriptionQueries(db);
  }

  async mint(body: AppLinkMintRequest): Promise<MintedToken> {
    const subscription = await this.appLinkSubscriptions.findWithGrantsById(body.subscription_id);
    // The subscription id comes from job hints or a deploy: mint only when the
    // subscription's consumer is the principal's own project.
    const principalProjectId = await this.principalProjectId(body);
    if (
      !subscription
      || !subscription.api_grant
      || !principalProjectId
      || subscription.consumer_project_id !== principalProjectId
    ) {
      throw new NotFoundException(`App-link subscription ${body.subscription_id} not found`);
    }
    const grant = subscription.api_grant;
    if (grant.revoked_at) {
      throw new UnauthorizedException('App-link grant is revoked');
    }

    const attemptId = await this.boundAttempt(body);

    const consumerProject = await this.projects.findById(subscription.consumer_project_id);
    if (!consumerProject) {
      throw new NotFoundException(`Project ${subscription.consumer_project_id} not found`);
    }

    const producerEnv = body.producer_env
      ?? subscription.producer_env_name
      ?? body.consumer_env
      ?? null;
    if (!producerEnv) {
      throw new UnauthorizedException('producer_env is required for app-link token minting');
    }
    if (grant.envs.length > 0 && !grant.envs.includes(producerEnv)) {
      throw new UnauthorizedException(`Producer env ${producerEnv} is not allowed by this app-link grant`);
    }

    const accessToken = this.authService.mintAppLinkToken({
      subscriptionId: subscription.id,
      consumerProjectId: subscription.consumer_project_id,
      consumerOrgId: consumerProject.org_id,
      consumerPrincipal: body.consumer_principal,
      consumerEnv: body.consumer_env ?? null,
      producerProjectId: grant.producer_project_id,
      producerEnv,
      apiName: grant.export_name,
      scopes: subscription.requested_scopes,
      ttlSeconds: body.ttl_seconds,
      ...(attemptId ? { attemptId } : {}),
    });

    const parts = accessToken.split('.');
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    await this.appLinkSubscriptions.recordTokenMint({
      subscription_id: subscription.id,
      principal: body.consumer_principal,
      audience: `project:${grant.producer_project_id}`,
    });

    return {
      access_token: accessToken,
      token_type: 'bearer',
      expires_at: payload.exp,
    };
  }

  /**
   * The attempt a job principal's token is bound to: it must be the job's
   * running attempt. Only job principals carry one.
   */
  private async boundAttempt(body: AppLinkMintRequest): Promise<string | undefined> {
    if (!body.attempt_id) return undefined;
    const principal = typeof body.consumer_principal === 'string' ? body.consumer_principal : '';
    if (!principal.startsWith('job:')) {
      throw new UnauthorizedException('attempt_id applies to job principals only');
    }
    if (!await isRunningAttempt(this.jobs, principal.slice('job:'.length), body.attempt_id)) {
      throw new UnauthorizedException('attempt_id is not the job\'s running attempt');
    }
    return body.attempt_id;
  }

  /**
   * The project an app-link token is minted for: the job's own project for a
   * `job:<id>` principal (a stated consumer_project_id must agree), otherwise
   * the stated consumer_project_id. Null when it cannot be established.
   */
  private async principalProjectId(body: {
    consumer_principal: string;
    consumer_project_id?: string | null;
  }): Promise<string | null> {
    const stated = typeof body.consumer_project_id === 'string' && body.consumer_project_id
      ? body.consumer_project_id
      : null;
    const principal = typeof body.consumer_principal === 'string' ? body.consumer_principal : '';
    if (principal.startsWith('job:')) {
      const job = await this.jobs.findById(principal.slice('job:'.length));
      if (!job) return null;
      if (stated && stated !== job.project_id) return null;
      return job.project_id;
    }
    return stated;
  }
}
