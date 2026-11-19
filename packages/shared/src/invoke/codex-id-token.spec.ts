import { describe, expect, it } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { codexAccountIdOf, CODEX_ID_TOKEN_ISSUER, verifiedCodexAccountId } from './codex-id-token.js';

/**
 * A Codex auth.json names its account in two places: the plain
 * `tokens.account_id` field, which anyone who can write the file sets, and the
 * account claim of the issuer-signed `id_token`. Only the signed claim counts.
 */
const issuerKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const otherKeys = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { keys: [{ ...issuerKeys.publicKey.export({ format: 'jwk' }), kid: 'issuer-1', alg: 'RS256', use: 'sig' }] };

function b64url(value: string | Buffer): string {
  return Buffer.from(value).toString('base64url');
}

function idToken(account: string, opts: { key?: typeof issuerKeys.privateKey; iss?: string; kid?: string } = {}): string {
  const header = b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: opts.kid ?? 'issuer-1' }));
  const payload = b64url(JSON.stringify({
    iss: opts.iss ?? CODEX_ID_TOKEN_ISSUER,
    sub: 'user_alice',
    'https://api.openai.com/auth': { chatgpt_account_id: account },
  }));
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${b64url(signer.sign(opts.key ?? issuerKeys.privateKey))}`;
}

function authJson(tokens: Record<string, unknown>): string {
  return JSON.stringify({ tokens: { access_token: 'at', refresh_token: 'rt', ...tokens } });
}

describe('Codex id_token account', () => {
  it('reads the account from the signed claim, never the plain field', async () => {
    const json = authJson({ account_id: 'acct_acme', id_token: idToken('acct_other') });
    expect(codexAccountIdOf(json)).toBe('acct_other');
    await expect(verifiedCodexAccountId(json, jwks)).resolves.toBe('acct_other');
  });

  it('refuses a token not signed by the issuer', async () => {
    await expect(verifiedCodexAccountId(authJson({ id_token: idToken('acct_acme', { key: otherKeys.privateKey }) }), jwks))
      .rejects.toThrow(/signature/);
    await expect(verifiedCodexAccountId(authJson({ id_token: idToken('acct_acme', { kid: 'unknown' }) }), jwks))
      .rejects.toThrow(/key/);
    await expect(verifiedCodexAccountId(authJson({ id_token: idToken('acct_acme', { iss: 'https://issuer.example' }) }), jwks))
      .rejects.toThrow(/issuer/);
  });

  it('refuses an auth.json without an id_token', async () => {
    await expect(verifiedCodexAccountId(authJson({ account_id: 'acct_acme' }), jwks)).rejects.toThrow(/id_token/);
    expect(codexAccountIdOf(authJson({ account_id: 'acct_acme' }))).toBeNull();
  });
});
