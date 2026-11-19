import {
  BadRequestException,
  Controller,
  Get,
  HttpException,
  HttpStatus,
  Param,
  Query,
  Redirect,
} from '@nestjs/common';
import { ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import { RequirePermission } from '../auth/permission.decorator.js';
import { Public } from '../auth/auth.decorator.js';
import { CurrentUser } from '../common/request-decorators.js';
import type { AuthUser } from '../auth/auth.types.js';
import {
  IntegrationsService,
  OAUTH_NO_AUTH_USER,
  oauthRedirectUri,
  type OAuthCallbackResult,
} from '../integrations/integrations.service.js';
import { createJsonLogger } from '@eve/shared';

const logger = createJsonLogger('api');

/**
 * Google Drive OAuth Flow (per-org BYOA credentials)
 *
 * Admins register their own GCP OAuth app via
 * POST /orgs/:org_id/integrations/providers/google_drive/config,
 * then start from GET /orgs/:org_id/integrations/google-drive/authorize.
 * Google redirects the browser back to
 * GET /integrations/google-drive/oauth/callback, which stores the code
 * against the state; the user who started it completes with
 * POST /integrations/google-drive/oauth/complete and their own token.
 */
@ApiTags('integrations')
@Controller()
export class GoogleDriveOAuthController {
  constructor(private readonly integrationsService: IntegrationsService) {}

  @RequirePermission('integrations:write')
  @Get('orgs/:org_id/integrations/google-drive/authorize')
  @Redirect()
  @ApiOperation({ summary: 'Redirect to Google OAuth for Drive access; the state is bound to the caller' })
  @ApiParam({ name: 'org_id', description: 'Organization ID' })
  async authorize(
    @Param('org_id') orgId: string,
    @CurrentUser() caller?: AuthUser,
  ): Promise<{ url: string }> {
    const appConfig = await this.integrationsService.getOAuthAppConfig(orgId, 'google_drive');
    if (!appConfig) {
      throw new BadRequestException(
        'No Google Drive OAuth app configured for this org. ' +
        'Register credentials first: eve integrations configure google-drive --client-id "..." --client-secret "..."',
      );
    }

    const state = await this.integrationsService.createOAuthState(
      'google_drive',
      appConfig.org_id,
      caller?.user_id ?? OAUTH_NO_AUTH_USER,
    );

    const url = new URL('https://accounts.google.com/o/oauth2/v2/auth');
    url.searchParams.set('client_id', appConfig.client_id);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', 'https://www.googleapis.com/auth/drive');
    url.searchParams.set('access_type', 'offline');
    url.searchParams.set('prompt', 'consent');
    url.searchParams.set('include_granted_scopes', 'true');
    url.searchParams.set('state', state);
    const redirectUri = oauthRedirectUri('google_drive');
    if (redirectUri) url.searchParams.set('redirect_uri', redirectUri);

    return { url: url.toString() };
  }

  @Public()
  @Get('integrations/google-drive/oauth/callback')
  @ApiOperation({ summary: 'Handle Google OAuth callback: stores the code for the user who started the install to complete' })
  async callback(
    @Query('code') code: string | undefined,
    @Query('state') state: string | undefined,
    @Query('error') error: string | undefined,
  ): Promise<OAuthCallbackResult> {
    if (error) {
      logger.warn({ event: 'google_drive.oauth.error', error });
      throw new HttpException(
        { ok: false, error: `Google OAuth error: ${error}` },
        HttpStatus.BAD_REQUEST,
      );
    }

    if (!code || !state) {
      throw new BadRequestException('Missing code or state parameter');
    }

    return this.integrationsService.acceptOAuthCallback('google_drive', state, code);
  }
}
