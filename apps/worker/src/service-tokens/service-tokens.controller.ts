import { BadRequestException, Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ServiceTokenRenewalService, type RenewalReport } from './service-token-renewal.service';

@Controller('service-tokens')
export class ServiceTokensController {
  constructor(private readonly renewal: ServiceTokenRenewalService) {}

  /**
   * Renew one environment's service tokens now (the API's
   * `rotate-service-tokens`): what was renewed, what a write in between held
   * back and what failed.
   */
  @Post('renew')
  @HttpCode(200)
  async renew(@Body() body: { env_id?: string }): Promise<RenewalReport> {
    if (!body?.env_id) {
      throw new BadRequestException('env_id is required');
    }
    return this.renewal.renewEnvironment(body.env_id);
  }
}
