/**
 * The account a Codex auth.json belongs to, from its signed `id_token`.
 *
 * An auth.json names its account twice: the plain `tokens.account_id`
 * field, which whoever writes the file chooses, and the account claim of the
 * `id_token` the issuer signed. A write-back from a job is accepted only when
 * the signed claim, checked against the issuer's published keys, names the
 * same account as the stored credential.
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

function idTokenOf(authJson: string): string | null {
  try {
    const parsed = JSON.parse(authJson) as { tokens?: { id_token?: unknown } };
    const token = parsed.tokens?.id_token;
    return typeof token === 'string' && token.split('.').length === 3 ? token : null;
  } catch {
    return null;
  }
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

/**
 * The account claim of an auth.json's id_token, after checking the token is
 * RS256-signed by one of the issuer's keys and names the issuer. Throws
 * otherwise.
 */
export async function verifiedCodexAccountId(authJson: string, jwks: Jwks): Promise<string> {
  const token = idTokenOf(authJson);
  if (!token) throw new Error('auth.json has no id_token');
  const [headerB64, payloadB64, signatureB64] = token.split('.');
  const header = decodeSegment(headerB64);
  const payload = decodeSegment(payloadB64);
  if (header.alg !== 'RS256') throw new Error(`id_token algorithm ${String(header.alg)} is not accepted`);
  const jwk = jwks.keys.find((key) => key.kid === header.kid && (key.kty === 'RSA'));
  if (!jwk) throw new Error(`id_token key ${String(header.kid)} is not one of the issuer's keys`);
  const valid = verifySignature(
    'RSA-SHA256',
    Buffer.from(`${headerB64}.${payloadB64}`),
    createPublicKey({ key: jwk, format: 'jwk' }),
    Buffer.from(signatureB64, 'base64url'),
  );
  if (!valid) throw new Error('id_token signature does not verify');
  if (payload.iss !== CODEX_ID_TOKEN_ISSUER) throw new Error(`id_token issuer ${String(payload.iss)} is not ${CODEX_ID_TOKEN_ISSUER}`);
  const account = accountClaim(payload);
  if (!account) throw new Error('id_token has no account claim');
  return account;
}
