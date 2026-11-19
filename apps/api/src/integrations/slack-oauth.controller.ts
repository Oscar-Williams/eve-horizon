import {
  BadRequestException,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Query,
  Redirect,
  Req,
  Res,
} from '@nestjs/common';
import { ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import type { FastifyReply, FastifyRequest } from 'fastify';
import { RequirePermission } from '../auth/permission.decorator.js';
import { Public } from '../auth/auth.decorator.js';
import { CurrentUser } from '../common/request-decorators.js';
import type { AuthUser } from '../auth/auth.types.js';
import {
  IntegrationsService,
  OAUTH_NO_AUTH_USER,
  SLACK_INSTALL_COOKIE,
  oauthRedirectUri,
  type OAuthCallbackResult,
} from './integrations.service.js';
import { createJsonLogger } from '@eve/shared';

const logger = createJsonLogger('api');

const SLACK_SCOPES = [
  'app_mentions:read', 'chat:write', 'chat:write.public',
  'channels:history', 'channels:read',
  'groups:history', 'groups:read',
  'im:history', 'im:read', 'im:write',
  'users:read', 'users:read.email',
  'reactions:read', 'files:read',
].join(',');

/**
 * Slack OAuth Install Flow (per-org BYOA credentials)
 *
 * Admins register their own Slack app via
 * POST /orgs/:org_id/integrations/providers/slack/config,
 * then start from GET /orgs/:org_id/integrations/slack/authorize. Slack
 * redirects the browser back to GET /integrations/slack/oauth/callback,
 * which stores the code against the state; the user who started the
 * install completes it with POST /integrations/slack/oauth/complete and
 * their own token. The signed-link install (no Eve user) is bound to a
 * cookie instead, and completes at the callback.
 */
@ApiTags('integrations')
@Controller()
export class SlackOAuthController {
  constructor(private readonly integrationsService: IntegrationsService) {}

  @RequirePermission('integrations:write')
  @Get('orgs/:org_id/integrations/slack/authorize')
  @Redirect()
  @ApiOperation({ summary: 'Redirect to Slack OAuth for workspace install; the state is bound to the caller' })
  @ApiParam({ name: 'org_id', description: 'Organization ID' })
  async authorize(
    @Param('org_id') orgId: string,
    @CurrentUser() caller?: AuthUser,
  ): Promise<{ url: string }> {
    const appConfig = await this.integrationsService.getOAuthAppConfig(orgId, 'slack');
    if (!appConfig) {
      throw new BadRequestException(
        'No Slack OAuth app configured for this org. ' +
        'Register credentials first: eve integrations configure slack --client-id "..." --client-secret "..." --signing-secret "..."',
      );
    }

    const state = await this.integrationsService.createOAuthState(
      'slack',
      appConfig.org_id,
      caller?.user_id ?? OAUTH_NO_AUTH_USER,
    );
    return { url: slackAuthorizeUrl(appConfig.client_id, state) };
  }

  @Public()
  @Get('integrations/slack/install')
  @Redirect()
  @ApiOperation({ summary: 'Public Slack install via signed token (no Eve auth required); bound to this browser by a cookie' })
  async install(
    @Query('token') token: string | undefined,
    @Res({ passthrough: true }) reply: FastifyReply,
  ): Promise<{ url: string }> {
    if (!token) {
      throw new BadRequestException('Missing token parameter');
    }

    const result = this.integrationsService.validateSlackInstallToken(token);
    if (!result) {
      throw new BadRequestException('Invalid, expired, or already-used install token');
    }

    const appConfig = await this.integrationsService.getOAuthAppConfig(result.orgId, 'slack');
    if (!appConfig) {
      throw new BadRequestException('No Slack OAuth app configured for this org');
    }

    const { state, cookie, maxAgeSeconds } = await this.integrationsService.createInstallOAuthState(appConfig.org_id);
    // __Host-: Secure, path /, no Domain. Lax, so the browser sends it on Slack's top-level redirect back.
    reply.header('set-cookie', installCookie(cookie, maxAgeSeconds));
    return { url: slackAuthorizeUrl(appConfig.client_id, state) };
  }

  @Public()
  @Get('integrations/slack/oauth/callback')
  @ApiOperation({
    summary: 'Handle Slack OAuth callback: stores the code for the user who started the install to complete; ' +
      'a signed-link install completes here with its cookie',
  })
  async callback(
    @Query('code') code: string | undefined,
    @Query('state') state: string | undefined,
    @Query('error') error: string | undefined,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) reply?: FastifyReply,
  ): Promise<OAuthCallbackResult> {
    if (error) {
      logger.warn({ event: 'slack.oauth.error', error });
      throw new HttpException({ ok: false, error: `Slack OAuth error: ${error}` }, HttpStatus.BAD_REQUEST);
    }

    if (!code || !state) {
      throw new BadRequestException('Missing code or state parameter');
    }

    const cookie = readCookie(req.headers?.cookie, SLACK_INSTALL_COOKIE);
    const result = await this.integrationsService.acceptOAuthCallback('slack', state, code, cookie);
    if (cookie !== undefined && !result.pending) {
      reply?.header('set-cookie', installCookie('', 0));
    }
    return result;
  }
}

function slackAuthorizeUrl(clientId: string, state: string): string {
  const url = new URL('https://slack.com/oauth/v2/authorize');
  url.searchParams.set('client_id', clientId);
  url.searchParams.set('scope', SLACK_SCOPES);
  url.searchParams.set('state', state);
  const redirectUri = oauthRedirectUri('slack');
  if (redirectUri) url.searchParams.set('redirect_uri', redirectUri);
  return url.toString();
}

function installCookie(value: string, maxAgeSeconds: number): string {
  return `${SLACK_INSTALL_COOKIE}=${value}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeconds}`;
}

/** One cookie's value from a Cookie header. */
export function readCookie(header: string | string[] | undefined, name: string): string | undefined {
  const raw = Array.isArray(header) ? header.join('; ') : header;
  if (!raw) return undefined;
  for (const part of raw.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return undefined;
}
