import { Module } from '@nestjs/common';
import { DeployerModule } from '../deployer/deployer.module';
import {
  ApiServiceTokenIssuer,
  SERVICE_TOKEN_ISSUER,
  ServiceTokenRenewalService,
} from './service-token-renewal.service';
import { ServiceTokensController } from './service-tokens.controller';

@Module({
  imports: [DeployerModule],
  controllers: [ServiceTokensController],
  providers: [
    ServiceTokenRenewalService,
    { provide: SERVICE_TOKEN_ISSUER, useClass: ApiServiceTokenIssuer },
  ],
  exports: [ServiceTokenRenewalService],
})
export class ServiceTokensModule {}
