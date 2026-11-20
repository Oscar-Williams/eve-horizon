import { BadRequestException, Body, Controller, HttpCode, Post } from '@nestjs/common';
import { ServiceTokenRenewalService, type RenewedToken } from './service-token-renewal.service';

@Controller('service-tokens')
export class ServiceTokensController {
  constructor(private readonly renewal: ServiceTokenRenewalService) {}

  /** Renew one environment's service tokens now (the API's `rotate-service-tokens`). */
  @Post('renew')
  @HttpCode(200)
  async renew(@Body() body: { env_id?: string }): Promise<{ renewed: RenewedToken[] }> {
    if (!body?.env_id) {
      throw new BadRequestException('env_id is required');
    }
    return { renewed: await this.renewal.renewEnvironment(body.env_id) };
  }
}
