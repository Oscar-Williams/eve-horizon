import { CanActivate, ExecutionContext, Inject, Injectable, Optional, UnauthorizedException } from '@nestjs/common';
import { internalLegacyKeyDecider, type Db } from '@eve/db';
import { identifyInternalCaller, internalTokenMatches, legacyInternalKeyJudge, SERVICE_KEY_HEADER } from '@eve/shared';

/**
 * Guard to protect internal admin endpoints.
 *
 * Accepts the core service key (`x-eve-service-key: core.<key>`), or the
 * legacy EVE_INTERNAL_API_KEY via:
 * - `x-internal-api-key` header, OR
 * - `Authorization: Bearer <key>` header
 *
 * A call that only the legacy key proves follows the instance's
 * `internal.service_key`, as at the worker and agent runtime: recorded under
 * `audit`, refused under `strict`.
 *
 * If no key is configured, all requests are REJECTED (fail closed).
 */
@Injectable()
export class InternalApiKeyGuard implements CanActivate {
  private readonly legacyKeyAllowed?: (path: string) => Promise<boolean>;

  constructor(@Optional() @Inject('DB') db?: Db) {
    this.legacyKeyAllowed = db ? legacyInternalKeyJudge(internalLegacyKeyDecider(db, 'orchestrator')) : undefined;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const headers = request?.headers;

    if (headers && identifyInternalCaller(headers[SERVICE_KEY_HEADER]) === 'core') {
      return true;
    }

    const configuredKey = process.env.EVE_INTERNAL_API_KEY;

    // Fail closed: if no key is configured, reject all requests
    if (!configuredKey) {
      throw new UnauthorizedException('Internal API key not configured');
    }

    if (!headers) {
      throw new UnauthorizedException('Missing headers');
    }

    // Try x-internal-api-key header first
    let providedKey = headers['x-internal-api-key'];
    if (Array.isArray(providedKey)) {
      providedKey = providedKey[0];
    }

    // Fallback to Authorization: Bearer <key>
    if (!providedKey) {
      const authorization = headers.authorization;
      const authHeader = Array.isArray(authorization) ? authorization[0] : authorization;
      if (authHeader) {
        const match = authHeader.match(/^Bearer\s+(.+)$/i);
        if (match) {
          providedKey = match[1];
        }
      }
    }

    if (!providedKey) {
      throw new UnauthorizedException('Missing internal API key');
    }

    // Constant-time comparison (shared helper; does not leak the key's length)
    if (!internalTokenMatches(providedKey, configuredKey)) {
      throw new UnauthorizedException('Invalid internal API key');
    }

    const url: string = typeof request.url === 'string' ? request.url : '';
    const path = url.split('?')[0];
    if (this.legacyKeyAllowed && !(await this.legacyKeyAllowed(path))) {
      throw new UnauthorizedException('The legacy internal key is refused (rule internal.service_key)');
    }

    return true;
  }
}
