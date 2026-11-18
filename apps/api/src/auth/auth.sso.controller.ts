import { Body, Controller, HttpCode, HttpStatus, Headers, Post, UnauthorizedException } from '@nestjs/common';
import { ApiBody, ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { z } from 'zod';
import { zodSchemaToOpenApi } from '../openapi.js';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe.js';
import { Public } from './auth.decorator.js';
import { SsoSessionService } from './sso-session.service.js';

const SsoOriginCheckRequestSchema = z.object({
  origin: z.string().max(2048).nullish(),
  project_id: z.string().max(256).nullish(),
  purpose: z.enum(['session', 'logout']),
});
type SsoOriginCheckRequest = z.infer<typeof SsoOriginCheckRequestSchema>;

const SsoOriginCheckResponseSchema = z.object({
  profile: z.enum(['legacy', 'audit', 'strict']),
  allowed: z.boolean(),
});
type SsoOriginCheckResponse = z.infer<typeof SsoOriginCheckResponseSchema>;

const SsoSessionRequestSchema = z.object({
  origin: z.string().max(2048).nullish(),
  project_id: z.string().max(256).nullish(),
});
type SsoSessionRequest = z.infer<typeof SsoSessionRequestSchema>;

const SsoSessionResponseSchema = z.object({
  access_token: z.string(),
  token_type: z.string(),
  expires_at: z.number(),
  user_id: z.string(),
  audience: z.string().optional(),
});
type SsoSessionResponse = z.infer<typeof SsoSessionResponseSchema>;

/**
 * Decisions the SSO asks for before it serves /session and /logout, under the
 * instance security profile (rules sso.session_origin, sso.app_access and
 * sso.audience_token).
 */
@ApiTags('auth')
@Controller('auth/sso')
export class AuthSsoController {
  constructor(private readonly sessions: SsoSessionService) {}

  @Post('check-origin')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Check an origin asking the SSO for a session or sign-out',
    description:
      'Returns the instance security profile and whether the Origin may use the SSO /session or ' +
      '/logout: the Eve dashboard with no project, or an https host of the named project with ' +
      'x-eve.auth. An origin that may not is recorded as a security finding.',
  })
  @ApiBody({ schema: zodSchemaToOpenApi(SsoOriginCheckRequestSchema, 'SsoOriginCheckRequest') })
  @ApiOkResponse({ schema: zodSchemaToOpenApi(SsoOriginCheckResponseSchema, 'SsoOriginCheckResponse') })
  async checkOrigin(
    @Body(new ZodValidationPipe(SsoOriginCheckRequestSchema)) body: SsoOriginCheckRequest,
  ): Promise<SsoOriginCheckResponse> {
    return this.sessions.checkOrigin(body);
  }

  @Post('session')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Issue the token the SSO /session returns',
    description:
      'Takes a GoTrue access token as the Bearer and the Origin and project the browser asked from. ' +
      'The dashboard gets the platform token. Under the strict instance profile an app gets an ' +
      'audience token (aud eve-app:<project>[:<env>], one hour, no orgs claim), only for a person its ' +
      'app-access policy admits; other callers get 403.',
  })
  @ApiBody({ schema: zodSchemaToOpenApi(SsoSessionRequestSchema, 'SsoSessionRequest') })
  @ApiOkResponse({ schema: zodSchemaToOpenApi(SsoSessionResponseSchema, 'SsoSessionResponse') })
  async session(
    @Headers('authorization') authorization: string | string[] | undefined,
    @Body(new ZodValidationPipe(SsoSessionRequestSchema)) body: SsoSessionRequest,
  ): Promise<SsoSessionResponse> {
    const header = Array.isArray(authorization) ? authorization[0] : authorization;
    if (!header?.startsWith('Bearer ')) {
      throw new UnauthorizedException('Bearer token required');
    }
    return this.sessions.issueSessionToken(header.slice('Bearer '.length), body);
  }
}
