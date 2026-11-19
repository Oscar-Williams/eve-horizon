import { createHash, timingSafeEqual } from 'node:crypto';

/**
 * Internal service keys.
 *
 * Platform services authenticate to each other with a key per service:
 *
 * - `core`: one key shared by the API, worker, orchestrator and agent
 *   runtime (`EVE_INTERNAL_CORE_KEY`). They all hold the database URL, so
 *   separate keys between them would add no wall.
 * - `gateway` and `sso`: their own keys (`EVE_INTERNAL_GATEWAY_KEY`,
 *   `EVE_INTERNAL_SSO_KEY`). A callee holds only SHA-256 hashes of them
 *   (`EVE_INTERNAL_CALLER_HASHES=gateway:<hex>,sso:<hex>`), so it cannot act
 *   as them. The API accepts them only on the routes that declare them.
 *
 * A caller sends `x-eve-service-key: <service>.<key>`. While it still holds
 * the legacy `EVE_INTERNAL_API_KEY`, it also sends `x-eve-internal-token`,
 * so a callee not yet upgraded keeps working; removing the legacy key from
 * its env stops that.
 */

/** Header carrying `<service>.<key>`. */
export const SERVICE_KEY_HEADER = 'x-eve-service-key';

/** Header carrying the legacy shared key (`EVE_INTERNAL_API_KEY`). */
export const INTERNAL_TOKEN_HEADER = 'x-eve-internal-token';

export const INTERNAL_KEY_SERVICES = ['core', 'gateway', 'sso'] as const;
export type InternalKeyService = (typeof INTERNAL_KEY_SERVICES)[number];

/** The env var holding each service's own key. */
export const INTERNAL_KEY_ENV: Readonly<Record<InternalKeyService, string>> = {
  core: 'EVE_INTERNAL_CORE_KEY',
  gateway: 'EVE_INTERNAL_GATEWAY_KEY',
  sso: 'EVE_INTERNAL_SSO_KEY',
};

/** The env var listing `<service>:<sha256 hex>` for keys a callee accepts without holding them. */
export const INTERNAL_CALLER_HASHES_ENV = 'EVE_INTERNAL_CALLER_HASHES';

type Env = Record<string, string | undefined>;

function digest(value: string): Buffer {
  return createHash('sha256').update(value, 'utf8').digest();
}

function isInternalKeyService(value: string): value is InternalKeyService {
  return (INTERNAL_KEY_SERVICES as readonly string[]).includes(value);
}

/**
 * Check a presented legacy internal token against `EVE_INTERNAL_API_KEY` in
 * constant time. Fails closed: an unset key, or a missing, empty or
 * non-string token, never matches. Both values are hashed before comparison
 * so neither the key's content nor its length leaks through timing.
 */
export function internalTokenMatches(presented: unknown, expected: string | undefined): boolean {
  if (!expected || typeof presented !== 'string' || presented.length === 0) {
    return false;
  }
  return timingSafeEqual(digest(presented), digest(expected));
}

/** The SHA-256 (hex) of a key, as `EVE_INTERNAL_CALLER_HASHES` lists it. */
export function internalKeyHash(key: string): string {
  return digest(key).toString('hex');
}

/**
 * Headers that authenticate a call as `service` (core unless named): the
 * service key, and the legacy key while the env still holds it. Nothing when
 * neither is set, which the callee refuses (the fail-closed outcome).
 */
export function internalAuthHeaders(
  options: { service?: InternalKeyService; env?: Env; legacyKey?: string } = {},
): Record<string, string> {
  const service = options.service ?? 'core';
  const env = options.env ?? process.env;
  const headers: Record<string, string> = {};
  const key = env[INTERNAL_KEY_ENV[service]];
  if (key) headers[SERVICE_KEY_HEADER] = `${service}.${key}`;
  const legacy = options.legacyKey ?? env.EVE_INTERNAL_API_KEY;
  if (legacy) headers[INTERNAL_TOKEN_HEADER] = legacy;
  return headers;
}

/** True when the service holds its own key or the legacy key. */
export function hasInternalCredential(options: { service?: InternalKeyService; env?: Env } = {}): boolean {
  const env = options.env ?? process.env;
  return Boolean(env[INTERNAL_KEY_ENV[options.service ?? 'core']] || env.EVE_INTERNAL_API_KEY);
}

/**
 * The key hashes a callee accepts: those in `EVE_INTERNAL_CALLER_HASHES`,
 * plus the core key's own hash when the callee holds the core key.
 * Malformed entries are ignored.
 */
function acceptedHashes(env: Env): Map<InternalKeyService, Buffer> {
  const hashes = new Map<InternalKeyService, Buffer>();
  for (const entry of (env[INTERNAL_CALLER_HASHES_ENV] ?? '').split(',')) {
    const [service, hex] = entry.trim().split(':');
    if (!service || !hex || !isInternalKeyService(service) || !/^[0-9a-f]{64}$/i.test(hex)) continue;
    hashes.set(service, Buffer.from(hex, 'hex'));
  }
  const core = env[INTERNAL_KEY_ENV.core];
  if (core) hashes.set('core', digest(core));
  return hashes;
}

/**
 * The service a presented `<service>.<key>` proves, or null. The key must
 * hash to the value the callee holds for that service name, so a key can
 * never pass under another service's name.
 */
export function identifyInternalCaller(presented: unknown, env: Env = process.env): InternalKeyService | null {
  if (typeof presented !== 'string') return null;
  const dot = presented.indexOf('.');
  if (dot <= 0 || dot === presented.length - 1) return null;
  const service = presented.slice(0, dot);
  if (!isInternalKeyService(service)) return null;
  const expected = acceptedHashes(env).get(service);
  if (!expected) return null;
  return timingSafeEqual(digest(presented.slice(dot + 1)), expected) ? service : null;
}

export type InternalCall =
  | { kind: 'service'; service: InternalKeyService }
  /** Only the legacy key proved the call; `serviceKeyRefused` when a service key was sent but did not verify. */
  | { kind: 'legacy'; serviceKeyRefused: boolean };

/**
 * Who made an internal call. A call with a service key the callee can
 * verify is judged on that key alone, whatever else it sends. A service key
 * the callee cannot verify (for example before its hashes are configured)
 * falls back to the legacy key. Null when nothing verifies.
 */
export function judgeInternalCall(
  headers: Record<string, string | string[] | undefined> | undefined,
  options: { env?: Env; legacyKey?: string } = {},
): InternalCall | null {
  const env = options.env ?? process.env;
  const serviceKey = headers?.[SERVICE_KEY_HEADER];
  const sentServiceKey = typeof serviceKey === 'string' && serviceKey.length > 0;
  if (sentServiceKey) {
    const service = identifyInternalCaller(serviceKey, env);
    if (service) return { kind: 'service', service };
  }
  if (internalTokenMatches(headers?.[INTERNAL_TOKEN_HEADER], options.legacyKey ?? env.EVE_INTERNAL_API_KEY)) {
    return { kind: 'legacy', serviceKeyRefused: sentServiceKey };
  }
  return null;
}
