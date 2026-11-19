// App-link tokens (type app_link, aud project:<producer>) are not app
// audience tokens: the SDK verifies them as it did before app audiences, with
// no eve-app: audience check and no X-Eve-Audience header.
//
// Runs on the built package: `pnpm --filter @eve-horizon/auth test`.
import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { eveAuthMe, verifyEveToken, verifyEveTokenRemote } from '../dist/index.js';

const API = 'https://api.eve.test';
const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = keyPair.publicKey.export({ format: 'jwk' });

function sign(claims) {
  const header = Buffer.from(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: 'sdk-test' })).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  const body = Buffer.from(JSON.stringify({ iat: now, exp: now + 300, ...claims })).toString('base64url');
  const signer = createSign('RSA-SHA256');
  signer.update(`${header}.${body}`);
  return `${header}.${body}.${signer.sign(keyPair.privateKey).toString('base64url')}`;
}

const APP_LINK_CLAIMS = {
  sub: 'app_link:sub_1',
  type: 'app_link',
  subscription_id: 'sub_1',
  aud: 'project:proj_producer',
  consumer_project_id: 'proj_consumer',
  consumer_org_id: 'org_c',
  consumer_principal: 'job:job_1',
  producer_project_id: 'proj_producer',
  producer_env: 'prod',
  api_name: 'observations',
  scopes: ['observations:read'],
};
const appLinkToken = () => sign(APP_LINK_CLAIMS);

let calls;
let realFetch;
let savedEnv;

beforeEach(() => {
  savedEnv = { ...process.env };
  process.env.EVE_PROJECT_ID = 'proj_producer';
  process.env.EVE_ENV_NAME = 'prod';
  process.env.EVE_API_URL = API;
  realFetch = globalThis.fetch;
  calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const headers = Object.fromEntries(new Headers(init.headers ?? {}).entries());
    calls.push({ url: String(url), headers });
    const path = new URL(String(url)).pathname;
    if (path === '/.well-known/jwks.json') {
      return Response.json({ keys: [{ kty: 'RSA', kid: 'sdk-test', alg: 'RS256', use: 'sig', n: jwk.n, e: jwk.e }] });
    }
    if (path === '/auth/token/verify') {
      return Response.json({ valid: true, type: 'app_link', user_id: 'app_link:sub_1', subscription_id: 'sub_1' });
    }
    if (path === '/auth/me') {
      return Response.json({ auth_enabled: true, authenticated: true, type: 'app_link', subscription_id: 'sub_1' });
    }
    return new Response('not found', { status: 404 });
  };
});

afterEach(() => {
  globalThis.fetch = realFetch;
  process.env = savedEnv;
});

describe('app-link tokens in a producer app', () => {
  it('verifyEveTokenRemote asks Eve, with no X-Eve-Audience, and returns its claims', async () => {
    const claims = await verifyEveTokenRemote(appLinkToken(), API);
    assert.equal(claims.type, 'app_link');
    const verify = calls.find((c) => c.url === `${API}/auth/token/verify`);
    assert.ok(verify, 'Eve /auth/token/verify was called');
    assert.equal(verify.headers['x-eve-audience'], undefined);
    assert.equal(claims.aud, undefined);
  });

  it('verifyEveToken (local) returns the app-link claims', async () => {
    const claims = await verifyEveToken(appLinkToken(), API);
    assert.equal(claims.type, 'app_link');
    assert.equal(claims.aud, undefined);
  });

  it('a project: audience is skipped the same way whatever the type says', async () => {
    const token = sign({ ...APP_LINK_CLAIMS, type: undefined });
    await assert.doesNotReject(verifyEveToken(token, API));
  });

  it('eveAuthMe asks Eve /auth/me with no X-Eve-Audience and answers with its reply', async () => {
    let body;
    const res = { status() { return this; }, json(value) { body = value; } };
    await eveAuthMe({ eveApiUrl: API, projectHeader: 'x-eve-project-id' })(
      { headers: { authorization: `Bearer ${appLinkToken()}`, 'x-eve-project-id': 'proj_producer' } },
      res,
    );
    assert.equal(body?.authenticated, true);
    const me = calls.find((c) => c.url === `${API}/auth/me`);
    assert.ok(me, 'Eve /auth/me was called');
    assert.equal(me.headers['x-eve-audience'], undefined);
  });

  it('still refuses an eve-app: token for another app', async () => {
    const token = sign({ sub: 'user_1', type: 'user', aud: 'eve-app:proj_other:prod' });
    await assert.rejects(verifyEveToken(token, API), /audience is not this app/);
    await assert.rejects(verifyEveTokenRemote(token, API), /audience is not this app/);
  });
});
