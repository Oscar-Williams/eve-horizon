import { Body, Controller, ForbiddenException, HttpCode, HttpStatus, Inject, NotFoundException, Param, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import { type Db, jobQueries } from '@eve/db';
import { RequirePermission } from './permission.decorator.js';
import { AuthService } from './auth.service.js';
import type { AuthUser } from './auth.types.js';
import { CurrentUser } from '../common/request-decorators.js';
import { AppLinkTokenMinter } from './app-link-token-minter.js';

/** The lifetime of an app-link token minted for a job (the runtime mints the first one with it too). */
const JOB_APP_LINK_TOKEN_TTL_SECONDS = 60 * 60;

type ResolvedAppLink = { name: string; alias?: string; subscription_id: string; producer_env?: string };

export interface JobAppLinkToken {
  alias: string;
  name: string;
  /** The harness env var that carried the job's first token for this link. */
  env_var: string;
  access_token: string;
  expires_at: number;
}

/** The env var name the runtime gives a link's token (buildAppApiEnvVars). */
export function appLinkTokenEnvVar(alias: string): string {
  return `EVE_APP_LINK_${alias.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_TOKEN`;
}

/**
 * Fresh app-link tokens for a running job. A job's app-link tokens last an
 * hour; a longer job calls this with its own job token before they expire.
 * The job token works only while the job runs, so a job that has ended gets
 * nothing. New tokens are bound to the caller's attempt like the first ones.
 */
@ApiTags('jobs')
@ApiBearerAuth()
@Controller('jobs/:job_id/app-link-tokens')
export class JobAppLinkTokensController {
  private readonly jobs: ReturnType<typeof jobQueries>;
  private readonly minter: AppLinkTokenMinter;

  constructor(authService: AuthService, @Inject('DB') db: Db) {
    this.jobs = jobQueries(db);
    this.minter = new AppLinkTokenMinter(authService, db);
  }

  @RequirePermission('jobs:read')
  @Post()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: "Mint fresh app-link tokens for a running job (the job's own token only)" })
  @ApiParam({ name: 'job_id', description: 'Job ID', type: String })
  async refresh(
    @Param('job_id') jobId: string,
    @Body() body: { alias?: string } | undefined,
    @CurrentUser() caller: AuthUser | undefined,
  ): Promise<{ data: JobAppLinkToken[] }> {
    if (!caller?.is_job_token || caller.job_id !== jobId) {
      throw new ForbiddenException("Only the job's own job token can refresh its app-link tokens");
    }
    const job = await this.jobs.findById(jobId);
    if (!job) {
      throw new NotFoundException(`Job ${jobId} not found`);
    }

    const links = ((job.hints?.resolved_app_links ?? []) as ResolvedAppLink[])
      .filter((link) => link && typeof link.subscription_id === 'string');
    const wanted = body?.alias
      ? links.filter((link) => (link.alias ?? link.name) === body.alias)
      : links;
    if (body?.alias && wanted.length === 0) {
      throw new NotFoundException(`Job ${jobId} has no app link "${body.alias}"`);
    }

    const data: JobAppLinkToken[] = [];
    for (const link of wanted) {
      const alias = link.alias ?? link.name;
      const minted = await this.minter.mint({
        subscription_id: link.subscription_id,
        consumer_principal: `job:${jobId}`,
        producer_env: link.producer_env ?? null,
        ttl_seconds: JOB_APP_LINK_TOKEN_TTL_SECONDS,
        attempt_id: caller.attempt_id ?? null,
      });
      data.push({
        alias,
        name: link.name,
        env_var: appLinkTokenEnvVar(alias),
        access_token: minted.access_token,
        expires_at: minted.expires_at,
      });
    }
    return { data };
  }
}
