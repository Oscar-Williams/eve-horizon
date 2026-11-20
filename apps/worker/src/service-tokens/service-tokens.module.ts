import { Module } from '@nestjs/common';
import { DeployerModule } from '../deployer/deployer.module';
import {
  ApiServiceTokenIssuer,
  SERVICE_TOKEN_ISSUER,
  ServiceTokenRenewalService,
} from './service-token-renewal.service';

@Module({
  imports: [DeployerModule],
  providers: [
    ServiceTokenRenewalService,
    { provide: SERVICE_TOKEN_ISSUER, useClass: ApiServiceTokenIssuer },
  ],
  exports: [ServiceTokenRenewalService],
})
export class ServiceTokensModule {}
