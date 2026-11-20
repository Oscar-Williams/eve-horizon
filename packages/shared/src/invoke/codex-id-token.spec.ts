import { describe, expect, it } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { codexAccountIdOf, CODEX_ID_TOKEN_ISSUER, verifiedCodexAccountId } from './codex-id-token.js';

/**
 * A Codex auth.json names its account in three places: the plain
 * `tokens.account_id` field, which anyone who can write the file sets, and the
 * account claims of the issuer-signed `id_token` and `access_token`. Only the
 * signed claims count, and the file is accepted only when all of them name
 * one account.
 */
const issuerKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { keys: [{ ...issuerKeys.publicKey.export({ format: 'jwk' }), kid: 'issuer-1', alg: 'RS256', use: 'sig' }] };
const NOW = Date.parse('2026-11-20T10:00:00Z');

function b64url(value: string | Buffer): string {
  return Buffer.from(value).toString('base64url');
}

function jwt(account: string, opts: { key?: typeof issuerKeys.privateKey; iss?: string; kid?: string; exp?: number } = {}): string {
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: opts.kid ?? 'issuer-1' }));
  const payload = b64url(JSON.stringify({
    iss: opts.iss ?? CODEX_ID_TOKEN_ISSUER,
    sub: 'user_alice',
    ...(opts.exp !== undefined ? { exp: opts.exp } : {}),
    'https://api.openai.com/auth': { chatgpt_account_id: account },
  }));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${b64url(signer.sign(opts.key ?? issuerKeys.privateKey))}`;
}

const idToken = jwt;
const accessToken = (account: string, opts: Parameters<typeof jwt>[1] = {}) =>
  jwt(account, { exp: NOW / 1000 + 3600, ...opts });

function authJson(tokens: Record<string, unknown>): string {
  return JSON.stringify({ tokens: { access_token: accessToken('acct_acme'), refresh_token: 'rt', ...tokens } });
}

describe('Codex id_token account', () => {
  it('reads the account from the signed claim, never the plain field', async () => {
    const json = authJson({ id_token: idToken('acct_other'), access_token: accessToken('acct_other') });
    expect(codexAccountIdOf(json)).toBe('acct_other');
    await expect(verifiedCodexAccountId(json, jwks, NOW)).resolves.toBe('acct_other');
  });

  it('refuses a token not signed by the issuer', async () => {
    await expect(verifiedCodexAccountId(authJson({ id_token: idToken('acct_acme', { key: otherKeys.privateKey }) }), jwks, NOW))
      .rejects.toThrow(/signature/);
    await expect(verifiedCodexAccountId(authJson({ id_token: idToken('acct_acme', { kid: 'unknown' }) }), jwks, NOW))
      .rejects.toThrow(/key/);
    await expect(verifiedCodexAccountId(authJson({ id_token: idToken('acct_acme', { iss: 'https://issuer.example' }) }), jwks, NOW))
      .rejects.toThrow(/issuer/);
  });

  it('refuses an auth.json without an id_token', async () => {
    await expect(verifiedCodexAccountId(authJson({ account_id: 'acct_acme' }), jwks, NOW)).rejects.toThrow(/id_token/);
    expect(codexAccountIdOf(authJson({ account_id: 'acct_acme' }))).toBeNull();
  });
});

describe('Codex auth.json: the access token and the plain account field', () => {
  it('accepts a file whose signed tokens and plain field name one account', async () => {
    const json = authJson({ id_token: idToken('acct_acme'), account_id: 'acct_acme' });
    await expect(verifiedCodexAccountId(json, jwks, NOW)).resolves.toBe('acct_acme');
  });

  it("refuses an access token of another account beside the stored account's id_token", async () => {
    const json = authJson({ id_token: idToken('acct_acme'), access_token: accessToken('acct_other') });
    await expect(verifiedCodexAccountId(json, jwks, NOW)).rejects.toThrow(/access_token/);
  });

  it('refuses an access token the issuer did not sign, or that is not a signed token at all', async () => {
    const forged = authJson({ id_token: idToken('acct_acme'), access_token: accessToken('acct_acme', { key: otherKeys.privateKey }) });
    await expect(verifiedCodexAccountId(forged, jwks, NOW)).rejects.toThrow(/access_token/);
    const opaque = authJson({ id_token: idToken('acct_acme'), access_token: 'at-opaque' });
    await expect(verifiedCodexAccountId(opaque, jwks, NOW)).rejects.toThrow(/access_token/);
    const otherIssuer = authJson({ id_token: idToken('acct_acme'), access_token: accessToken('acct_acme', { iss: 'https://issuer.example' }) });
    await expect(verifiedCodexAccountId(otherIssuer, jwks, NOW)).rejects.toThrow(/access_token/);
  });

  it('refuses an expired access token', async () => {
    const json = authJson({ id_token: idToken('acct_acme'), access_token: accessToken('acct_acme', { exp: NOW / 1000 - 3600 }) });
    await expect(verifiedCodexAccountId(json, jwks, NOW)).rejects.toThrow(/expired/);
  });

  it('refuses a plain account_id that differs from the signed claims', async () => {
    const json = authJson({ id_token: idToken('acct_acme'), account_id: 'acct_other' });
    await expect(verifiedCodexAccountId(json, jwks, NOW)).rejects.toThrow(/account_id/);
  });
});
