import { UnauthorizedException } from '@nestjs/common';
import { judgeInternalCall, legacyInternalKeyJudge, type SecurityProfile } from '@eve/shared';
import { postJson } from './api-client.js';

type Headers = Record<string, string | string[] | undefined>;

/**
 * `internal.service_key` for a call that only the legacy key proves. The
 * gateway holds no database, so the API decides the instance's profile and
 * records the finding; the answer is reused for half a minute. When the API
 * cannot answer, the call is let through as before this rule.
 */
export function gatewayLegacyKeyJudge(): (route: string) => Promise<boolean> {
  return legacyInternalKeyJudge(async (route) => {
    const { profile } = await postJson<{ profile: SecurityProfile }>('/internal/security/legacy-key-calls', { route });
    return profile;
  });
}

/**
 * Who may call the gateway's internal routes (`/internal/deliver` and
 * simulate): the services that deliver, with the deliver key
 * (`x-eve-service-key: deliver.<key>`; the gateway holds only its hash in
 * `EVE_INTERNAL_CALLER_HASHES`), or the legacy key while the gateway holds
 * it and `internal.service_key` allows it (`legacyKeyAllowed`). No other
 * service key passes, the core key included: the gateway never needs it, so
 * it is never sent here.
 */
export async function assertDeliverCaller(
  headers: Headers | undefined,
  route: string,
  legacyKeyAllowed: (route: string) => Promise<boolean>,
): Promise<void> {
  const call = judgeInternalCall(headers);
  if (!call || (call.kind === 'service' && call.service !== 'deliver')) {
    throw new UnauthorizedException('Missing or invalid internal token');
  }
  if (call.kind === 'legacy' && !(await legacyKeyAllowed(route))) {
    throw new UnauthorizedException('The legacy internal key is refused (rule internal.service_key)');
  }
}
