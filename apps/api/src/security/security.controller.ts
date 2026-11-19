import { Body, Controller, ForbiddenException, Get, HttpCode, HttpStatus, Put, Query } from '@nestjs/common';
import { ApiBearerAuth, ApiBody, ApiOkResponse, ApiOperation, ApiQuery, ApiTags } from '@nestjs/swagger';
import { SetSecurityProfileRequestSchema, type SetSecurityProfileRequest } from '@eve/shared';
import { RequirePermission } from '../auth/permission.decorator.js';
import { CurrentUser } from '../common/request-decorators.js';
import type { AuthUser } from '../auth/auth.types.js';
import { ZodValidationPipe } from '../pipes/zod-validation.pipe.js';
import { zodSchemaToOpenApi } from '../openapi.js';
import { SecurityService } from './security.service.js';

function requireSystemAdmin(caller: AuthUser | undefined): string {
  // No caller means authentication is disabled (local development), as in SystemController.
  if (!caller) return 'admin';
  if (!(caller.is_admin || caller.role === 'system_admin') || caller.bound_org_id) {
    throw new ForbiddenException('System admin scope required');
  }
  return caller.user_id;
}

@ApiTags('system')
@ApiBearerAuth()
@Controller('system/security')
export class SecurityController {
  constructor(private readonly security: SecurityService) {}

  @RequirePermission('system:admin')
  @Get('report')
  @ApiOperation({ summary: 'Security profiles and findings (system_admin only)' })
  @ApiQuery({ name: 'org_id', required: false })
  @ApiQuery({ name: 'project_id', required: false })
  @ApiQuery({ name: 'days', required: false, description: 'Findings window in days (1-90, default 14)' })
  @ApiOkResponse({ description: 'Effective profiles per org and project, and findings by rule' })
  async report(
    @CurrentUser() caller: AuthUser | undefined,
    @Query('org_id') orgId?: string,
    @Query('project_id') projectId?: string,
    @Query('days') days?: string,
  ) {
    requireSystemAdmin(caller);
    const parsedDays = days ? Number.parseInt(days, 10) : undefined;
    return this.security.report({
      orgId: orgId || undefined,
      projectId: projectId || undefined,
      days: Number.isFinite(parsedDays) ? parsedDays : undefined,
    });
  }

  @RequirePermission('system:admin')
  @Put('profile')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Set the security profile of the instance, new projects, an org or a project (system_admin only)' })
  @ApiBody({ schema: zodSchemaToOpenApi(SetSecurityProfileRequestSchema, 'SetSecurityProfileRequest') })
  @ApiOkResponse({ description: 'The profile now set' })
  async setProfile(
    @Body(new ZodValidationPipe(SetSecurityProfileRequestSchema)) body: SetSecurityProfileRequest,
    @CurrentUser() caller: AuthUser | undefined,
  ) {
    const actor = requireSystemAdmin(caller);
    return this.security.setProfile({ scope: body.scope, id: body.id } as never, body.profile, actor, { force: body.force });
  }
}
