import {
  Injectable,
  SetMetadata,
  UnauthorizedException,
  type CanActivate,
  type ExecutionContext,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { judgeInternalCall } from '@eve/shared';
import { SecurityService } from '../security/security.service.js';

/** Instance rule: the legacy key, and the gateway and SSO keys off their routes. */
export const INTERNAL_SERVICE_KEY_RULE = 'internal.service_key';

export const INTERNAL_CALLERS_KEY = 'eve:internal-callers';

/**
 * The services besides the core ones (API, worker, orchestrator, agent
 * runtime) whose key a route accepts. The gateway and the SSO declare each
 * route they call; the core key is accepted on every internal route.
 * Applies to a controller or a handler; a handler's declaration wins.
 */
export const InternalCallers = (...services: Array<'gateway' | 'sso'>) => SetMetadata(INTERNAL_CALLERS_KEY, services);

/**
 * Guards internal service-to-service endpoints.
 *
 * - `x-eve-service-key: core.<key>` (API, worker, orchestrator, agent
 *   runtime) passes on every route.
 * - The gateway's and the SSO's keys pass on the routes that declare them
 *   (`@InternalCallers`). Elsewhere `internal.service_key` decides: allowed
 *   under `legacy`, allowed and recorded under `audit`, 403 under `strict`.
 * - A call with only the legacy `x-eve-internal-token`
 *   (`EVE_INTERNAL_API_KEY`) is allowed under `legacy`, recorded under
 *   `audit` and refused with 401 under `strict`.
 * - A call with both is judged on the service key.
 *
 * Anything else is 401. Apply with `@UseGuards(InternalTokenGuard)` alongside
 * `@Public()` (which skips the global JWT auth guard).
 */
@Injectable()
export class InternalTokenGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly security: SecurityService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context
      .switchToHttp()
      .getRequest<{ headers: Record<string, string | string[] | undefined> }>();
    const call = judgeInternalCall(request.headers);
    if (!call) {
      throw new UnauthorizedException('Invalid internal token');
    }
    const route = `${context.getClass().name}.${context.getHandler().name}`;

    if (call.kind === 'service') {
      if (call.service === 'core') return true;
      const callers = this.reflector.getAllAndOverride<string[] | undefined>(INTERNAL_CALLERS_KEY, [
        context.getHandler(),
        context.getClass(),
      ]) ?? [];
      if (callers.includes(call.service)) return true;
      await this.security.gate(
        INTERNAL_SERVICE_KEY_RULE,
        {
          governing: 'instance',
          principal: { type: 'service', id: call.service },
          detail: { caller: call.service, route },
        },
        `The ${call.service} key is not accepted on this route`,
      );
      return true;
    }

    const profile = await this.security.decide(INTERNAL_SERVICE_KEY_RULE, {
      governing: 'instance',
      principal: { type: 'service', id: 'legacy-key' },
      detail: { caller: 'legacy-key', route, service_key_unverified: call.serviceKeyRefused },
    });
    if (profile === 'strict') {
      throw new UnauthorizedException(`The legacy internal key is refused (rule ${INTERNAL_SERVICE_KEY_RULE})`);
    }
    return true;
  }
}
