import { describe, expect, it, vi } from 'vitest';
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

  it("refuses an access token that names the issuer and one of its keys but is not signed with it", async () => {
    const forged = authJson({ id_token: idToken('acct_acme'), access_token: accessToken('acct_acme', { key: otherKeys.privateKey }) });
    await expect(verifiedCodexAccountId(forged, jwks, NOW)).rejects.toThrow(/access_token/);
  });

  it('compares only the decoded account claim of an access token from another issuer or an unknown key', async () => {
    for (const opts of [{ iss: 'https://issuer.example' }, { kid: 'unknown', key: otherKeys.privateKey }]) {
      const same = authJson({ id_token: idToken('acct_acme'), access_token: accessToken('acct_acme', opts) });
      await expect(verifiedCodexAccountId(same, jwks, NOW), JSON.stringify(opts)).resolves.toBe('acct_acme');
      const other = authJson({ id_token: idToken('acct_acme'), access_token: accessToken('acct_other', opts) });
      await expect(verifiedCodexAccountId(other, jwks, NOW), JSON.stringify(opts)).rejects.toThrow(/access_token/);
    }
  });

  it('says so when it accepts an access token on its decoded claims only, and not when the token verifies', async () => {
    for (const opts of [{ iss: 'https://issuer.example' }, { kid: 'unknown', key: otherKeys.privateKey }]) {
      const note = vi.fn();
      const json = authJson({ id_token: idToken('acct_acme'), access_token: accessToken('acct_acme', opts) });
      await expect(verifiedCodexAccountId(json, jwks, NOW, note)).resolves.toBe('acct_acme');
      expect(note, JSON.stringify(opts)).toHaveBeenCalledWith(expect.stringMatching(/access_token .*decoded claims only/));
    }
    const note = vi.fn();
    await expect(verifiedCodexAccountId(authJson({ id_token: idToken('acct_acme') }), jwks, NOW, note)).resolves.toBe('acct_acme');
    expect(note).not.toHaveBeenCalled();
  });

  it('skips the access token check, and says so, when the access token is not a JWT', async () => {
    for (const access of ['at-opaque', undefined]) {
      const note = vi.fn();
      const json = authJson({ id_token: idToken('acct_acme'), access_token: access, account_id: 'acct_acme' });
      await expect(verifiedCodexAccountId(json, jwks, NOW, note)).resolves.toBe('acct_acme');
      expect(note).toHaveBeenCalledWith(expect.stringMatching(/access_token is not a JWT/));
    }
    // The id_token and the plain field are still checked.
    const otherPlain = authJson({ id_token: idToken('acct_acme'), access_token: 'at-opaque', account_id: 'acct_other' });
    await expect(verifiedCodexAccountId(otherPlain, jwks, NOW)).rejects.toThrow(/account_id/);
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
