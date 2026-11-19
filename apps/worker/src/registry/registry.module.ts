import { Module } from '@nestjs/common';
import { DeployerModule } from '../deployer/deployer.module';
import { RegistryController } from './registry.controller.js';
import { RegistryPullSecretsService } from './registry-pull-secrets.service.js';

/** Registry pull secrets: re-signing them with the current registry credential key. */
@Module({
  imports: [DeployerModule],
  controllers: [RegistryController],
  providers: [RegistryPullSecretsService],
})
export class RegistryModule {}
