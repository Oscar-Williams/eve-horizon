// App audience tokens: the SSO gives a deployed app a user token whose `aud`
// names that app (eve-app:<project>:<env>, or eve-app:<project>). The SDK
// takes such a token only when the audience is the app's own, and sends it as
// X-Eve-Audience whenever it asks Eve about the token.
//
// Runs on the built package: `pnpm --filter @eve-horizon/auth test`.
import { afterEach, beforeEach, describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createSign, generateKeyPairSync } from 'node:crypto';
import {
  eveAppUserAuth,
  eveAuthMe,
  eveUserAuth,
  verifyEveToken,
  verifyEveTokenRemote,
} from '../dist/index.js';

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

const OWN = 'eve-app:proj_a:prod';
const appToken = (aud = OWN) => sign({ sub: 'user_1', type: 'user', email: 'person@example.com', aud });

let calls;
let realFetch;
let savedEnv;

function stubEve() {
  calls = [];
  globalThis.fetch = async (url, init = {}) => {
    const headers = Object.fromEntries(new Headers(init.headers ?? {}).entries());
    calls.push({ url: String(url), headers });
    const path = new URL(String(url)).pathname;
    if (path === '/.well-known/jwks.json') {
      return Response.json({ keys: [{ kty: 'RSA', kid: 'sdk-test', alg: 'RS256', use: 'sig', n: jwk.n, e: jwk.e }] });
    }
    if (path === '/auth/token/verify') {
      return Response.json({ valid: true, type: 'user', user_id: 'user_1', email: 'person@example.com' });
    }
    if (path === '/auth/app-access') {
      return Response.json({
        project_id: 'proj_a',
        orgs: [{ id: 'org_a', slug: 'a', name: 'A', role: 'admin', capabilities: { enter_app: true, invite_members: true } }],
        admin_orgs: [],
      });
    }
    if (path === '/auth/me') {
      return Response.json({ authenticated: true, type: 'user', user_id: 'user_1', memberships: [{ org_id: 'org_a', role: 'admin' }] });
    }
    return new Response('not found', { status: 404 });
  };
}

const callsTo = (path) => calls.filter((call) => new URL(call.url).pathname === path);

/** Run an Express-style middleware or handler to completion. */
async function run(middleware, req) {
  const res = {
    statusCode: 200,
    body: undefined,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; },
  };
  await new Promise((resolve) => {
    const out = middleware(req, res, resolve);
    Promise.resolve(out).then(() => { if (res.body !== undefined) resolve(); });
  });
  return res;
}

beforeEach(() => {
  realFetch = globalThis.fetch;
  savedEnv = { ...process.env };
  process.env.EVE_API_URL = API;
  process.env.EVE_PROJECT_ID = 'proj_a';
  process.env.EVE_ENV_NAME = 'prod';
  process.env.EVE_ORG_ID = 'org_a';
  stubEve();
});

afterEach(() => {
  globalThis.fetch = realFetch;
  process.env = savedEnv;
});

describe('verifyEveToken', () => {
  it("accepts a token for the app's own project and environment, and reports its audience", async () => {
    const claims = await verifyEveToken(appToken(), API);
    assert.equal(claims.user_id, 'user_1');
    assert.equal(claims.aud, OWN);
  });

  it("accepts a token for the app's own project that names no environment", async () => {
    const claims = await verifyEveToken(appToken('eve-app:proj_a'), API);
    assert.equal(claims.aud, 'eve-app:proj_a');
  });

  it('refuses a token for another project', async () => {
    await assert.rejects(verifyEveToken(appToken('eve-app:proj_b:prod'), API));
  });

  it("refuses a token for another of the project's environments", async () => {
    await assert.rejects(verifyEveToken(appToken('eve-app:proj_a:staging'), API));
  });

  it('refuses any audience when the process is not an app (no EVE_PROJECT_ID)', async () => {
    delete process.env.EVE_PROJECT_ID;
    await assert.rejects(verifyEveToken(appToken(), API));
  });

  it('accepts a token with no audience, as before', async () => {
    const claims = await verifyEveToken(sign({ sub: 'user_1', type: 'user', orgs: [] }), API);
    assert.equal(claims.aud, undefined);
  });
});

describe('verifyEveTokenRemote', () => {
  it("sends the token's audience as X-Eve-Audience", async () => {
    const claims = await verifyEveTokenRemote(appToken(), API);
    assert.equal(callsTo('/auth/token/verify')[0]?.headers['x-eve-audience'], OWN);
    assert.equal(claims.aud, OWN);
  });

  it('refuses a token for another app without asking Eve', async () => {
    await assert.rejects(verifyEveTokenRemote(appToken('eve-app:proj_b:prod'), API));
    assert.equal(callsTo('/auth/token/verify').length, 0);
  });

  it('sends no audience header for a token without one', async () => {
    await verifyEveTokenRemote(sign({ sub: 'user_1', type: 'user' }), API);
    assert.equal(callsTo('/auth/token/verify')[0]?.headers['x-eve-audience'], undefined);
  });
});

describe('middleware with an app audience token', () => {
  it('eveAppUserAuth sends the audience header to /auth/app-access', async () => {
    const req = { headers: { authorization: `Bearer ${appToken()}` }, query: {} };
    await run(eveAppUserAuth(), req);
    assert.equal(callsTo('/auth/app-access')[0]?.headers['x-eve-audience'], OWN);
    assert.equal(req.eveUser?.orgId, 'org_a');
  });

  it("eveUserAuth reads the person's org from /auth/app-access, as the token has no orgs claim", async () => {
    const req = { headers: { authorization: `Bearer ${appToken()}` }, query: {} };
    await run(eveUserAuth(), req);
    assert.equal(callsTo('/auth/app-access')[0]?.headers['x-eve-audience'], OWN);
    assert.deepEqual(req.eveUser, { id: 'user_1', email: 'person@example.com', orgId: 'org_a', role: 'admin' });
  });

  it('eveAuthMe asks Eve /auth/me with the audience header', async () => {
    const req = { headers: { authorization: `Bearer ${appToken()}` }, query: {} };
    const res = await run(eveAuthMe(), req);
    const me = callsTo('/auth/me')[0];
    assert.equal(me?.headers['x-eve-audience'], OWN);
    assert.deepEqual(res.body?.memberships, [{ org_id: 'org_a', role: 'admin' }]);
  });
});
