import { Body, Controller, HttpCode, HttpStatus, Param, Post } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOkResponse, ApiOperation, ApiParam, ApiTags } from '@nestjs/swagger';
import {
  OAuthCompleteRequestSchema,
  OAuthCompleteResponseSchema,
  type OAuthCompleteRequest,
  type OAuthCompleteResponse,
} from '@eve/shared';
import { zodSchemaToOpenApi } from '../openapi.js';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe.js';
import { CurrentUser } from '../common/request-decorators.js';
import type { AuthUser } from '../auth/auth.types.js';
import { IntegrationsService, OAUTH_NO_AUTH_USER } from './integrations.service.js';

/**
 * Finishing an OAuth install: the provider's public callback stored the
 * code; the user who started the install exchanges it here, with their own
 * token. Anyone else gets 403; before the browser has come back, 409.
 */
@ApiTags('integrations')
@ApiBearerAuth()
@Controller('integrations/:provider/oauth')
export class OAuthCompleteController {
  constructor(private readonly integrationsService: IntegrationsService) {}

  @Post('complete')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Complete an OAuth install (slack, google-drive) the caller started' })
  @ApiParam({ name: 'provider', description: 'slack or google-drive' })
  @ApiBody({ schema: zodSchemaToOpenApi(OAuthCompleteRequestSchema, 'OAuthCompleteRequest') })
  @ApiOkResponse({ schema: zodSchemaToOpenApi(OAuthCompleteResponseSchema, 'OAuthCompleteResponse') })
  async complete(
    @Param('provider') provider: string,
    @Body(new ZodValidationPipe(OAuthCompleteRequestSchema)) body: OAuthCompleteRequest,
    @CurrentUser() caller?: AuthUser,
  ): Promise<OAuthCompleteResponse> {
    return this.integrationsService.completeOAuth(provider, body.state, caller?.user_id ?? OAUTH_NO_AUTH_USER);
  }
}
