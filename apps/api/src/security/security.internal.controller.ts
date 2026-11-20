import { BadRequestException, Body, Controller, HttpCode, HttpStatus, Post, UseGuards } from '@nestjs/common';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import type { SecurityProfile } from '@eve/shared';
import { Public } from '../auth/auth.decorator.js';
import { INTERNAL_SERVICE_KEY_RULE, InternalCallers, InternalTokenGuard } from '../common/internal-token.guard.js';
import { SecurityService } from './security.service.js';

/**
 * Security decisions for platform services that hold no database. The
 * gateway asks here how to treat a call to its internal routes that only the
 * legacy internal key proved: the API decides `internal.service_key` for the
 * instance and records the finding, as the worker and agent runtime do for
 * their own calls. The gateway caches the answer briefly.
 */
@ApiTags('internal')
@Controller('internal/security')
@UseGuards(InternalTokenGuard)
@InternalCallers('gateway')
export class SecurityInternalController {
  constructor(private readonly security: SecurityService) {}

  @Post('legacy-key-calls')
  @Public()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Decide and record a legacy-key call the gateway received (internal only)' })
  async legacyKeyCall(@Body() body: { route: string }): Promise<{ profile: SecurityProfile }> {
    if (typeof body?.route !== 'string' || body.route.length === 0) {
      throw new BadRequestException('route is required');
    }
    const profile = await this.security.decide(INTERNAL_SERVICE_KEY_RULE, {
      governing: 'instance',
      principal: { type: 'service', id: 'legacy-key' },
      detail: { caller: 'legacy-key', callee: 'gateway', route: body.route.slice(0, 120) },
    });
    return { profile };
  }
}
