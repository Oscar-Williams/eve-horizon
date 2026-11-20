import { UnauthorizedException } from '@nestjs/common';
import { judgeInternalCall } from '@eve/shared';

type Headers = Record<string, string | string[] | undefined>;

/**
 * Who may call the gateway's internal routes (`/internal/deliver` and
 * simulate): the services that deliver, with the deliver key
 * (`x-eve-service-key: deliver.<key>`; the gateway holds only its hash in
 * `EVE_INTERNAL_CALLER_HASHES`), or the legacy key while the gateway holds
 * it. No other service key passes, the core key included: the gateway never
 * needs it, so it is never sent here.
 */
export function assertDeliverCaller(headers: Headers | undefined): void {
  const call = judgeInternalCall(headers);
  if (!call || (call.kind === 'service' && call.service !== 'deliver')) {
    throw new UnauthorizedException('Missing or invalid internal token');
  }
}
