import { ConflictException, Controller, HttpCode, Post } from '@nestjs/common';
import { RegistryPullSecretsService, type RegistryResignReport } from './registry-pull-secrets.service.js';

@Controller('registry')
export class RegistryController {
  constructor(private readonly pullSecrets: RegistryPullSecretsService) {}

  /** Re-sign stale environments' registry pull secrets with the current registry credential key. */
  @Post('pull-secrets/resign')
  @HttpCode(200)
  async resign(): Promise<RegistryResignReport> {
    if (!process.env.EVE_REGISTRY_CREDENTIAL_KEY) {
      throw new ConflictException(
        'EVE_REGISTRY_CREDENTIAL_KEY is not set on the worker: there is no current registry key to re-sign with',
      );
    }
    return this.pullSecrets.resign();
  }
}
