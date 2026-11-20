/**
 * The account a Codex auth.json belongs to, from its signed tokens.
 *
 * An auth.json names its account three times: the plain `tokens.account_id`
 * field, which whoever writes the file chooses, and the account claims of
 * the `id_token` and `access_token` the issuer signed. A write-back from a
 * job is accepted only when both signed claims, checked against the issuer's
 * published keys, name one account (the stored credential's), the access
 * token has not expired, and the plain field, when present, names it too.
 * The refresh token is opaque and cannot be checked here.
 */

import { createPublicKey, verify as verifySignature, type JsonWebKey } from 'node:crypto';

export const CODEX_ID_TOKEN_ISSUER = 'https://auth.openai.com';
export const CODEX_ID_TOKEN_JWKS_URL = 'https://auth.openai.com/.well-known/jwks.json';
const ACCOUNT_CLAIM = 'https://api.openai.com/auth';

export interface Jwks {
  keys: Array<JsonWebKey & { kid?: string; alg?: string }>;
}

function decodeSegment(segment: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8')) as Record<string, unknown>;
}

function tokensOf(authJson: string): Record<string, unknown> | null {
  try {
    const tokens = (JSON.parse(authJson) as { tokens?: unknown }).tokens;
    return tokens && typeof tokens === 'object' && !Array.isArray(tokens) ? tokens as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function jwtOf(value: unknown): string | null {
  return typeof value === 'string' && value.split('.').length === 3 ? value : null;
}

function idTokenOf(authJson: string): string | null {
  return jwtOf(tokensOf(authJson)?.id_token);
}

function accountClaim(payload: Record<string, unknown>): string | null {
  const auth = payload[ACCOUNT_CLAIM] as { chatgpt_account_id?: unknown } | undefined;
  return typeof auth?.chatgpt_account_id === 'string' && auth.chatgpt_account_id ? auth.chatgpt_account_id : null;
}

/**
 * The account claim of an auth.json's id_token, without checking its
 * signature: for the stored credential, which Eve already holds. Null when
 * the file has no readable id_token or claim.
 */
export function codexAccountIdOf(authJson: string): string | null {
  const token = idTokenOf(authJson);
  if (!token) return null;
  try {
    return accountClaim(decodeSegment(token.split('.')[1]));
  } catch {
    return null;
  }
}

/** A token's payload, after checking it is RS256-signed by one of the issuer's keys and names the issuer. */
function verifiedPayload(token: string, jwks: Jwks, label: string): Record<string, unknown> {
  const [headerB64, payloadB64, signatureB64] = token.split('.');
  const header = decodeSegment(headerB64);
  const payload = decodeSegment(payloadB64);
  if (header.alg !== 'RS256') throw new Error(`${label} algorithm ${String(header.alg)} is not accepted`);
  const jwk = jwks.keys.find((key) => key.kid === header.kid && (key.kty === 'RSA'));
  if (!jwk) throw new Error(`${label} key ${String(header.kid)} is not one of the issuer's keys`);
  const valid = verifySignature(
    'RSA-SHA256',
    Buffer.from(`${headerB64}.${payloadB64}`),
    createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(signatureB64, 'base64url'),
  );
  if (!valid) throw new Error(`${label} signature does not verify`);
  if (payload.iss !== CODEX_ID_TOKEN_ISSUER) throw new Error(`${label} issuer ${String(payload.iss)} is not ${CODEX_ID_TOKEN_ISSUER}`);
  return payload;
}

/** Clock skew allowed on the access token's expiry. */
const EXPIRY_SKEW_SECONDS = 60;

/**
 * The account an auth.json belongs to, after checking that its id_token and
 * access_token are both signed by the issuer and name the same account, that
 * the access token has not expired (when it carries `exp`), and that the
 * plain `tokens.account_id`, when present, names that account too. Throws
 * otherwise.
 */
export async function verifiedCodexAccountId(authJson: string, jwks: Jwks, now: number = Date.now()): Promise<string> {
  const idToken = idTokenOf(authJson);
  if (!idToken) throw new Error('auth.json has no id_token');
  const account = accountClaim(verifiedPayload(idToken, jwks, 'id_token'));
  if (!account) throw new Error('id_token has no account claim');

  const tokens = tokensOf(authJson) ?? {};
  const accessToken = jwtOf(tokens.access_token);
  if (!accessToken) throw new Error('auth.json has no signed access_token');
  const access = verifiedPayload(accessToken, jwks, 'access_token');
  if (accountClaim(access) !== account) throw new Error("access_token names another account than the id_token's");
  if (typeof access.exp === 'number' && access.exp + EXPIRY_SKEW_SECONDS < now / 1000) {
    throw new Error('access_token has expired');
  }

  if (tokens.account_id !== undefined && tokens.account_id !== null && tokens.account_id !== account) {
    throw new Error("tokens.account_id names another account than the signed tokens'");
  }
  return account;
}

/** The API key an auth.json carries (`OPENAI_API_KEY`), or null. */
export function codexApiKeyOf(authJson: string): string | null {
  try {
    const key = (JSON.parse(authJson) as { OPENAI_API_KEY?: unknown }).OPENAI_API_KEY;
    return typeof key === 'string' && key ? key : null;
  } catch {
    return null;
  }
}
