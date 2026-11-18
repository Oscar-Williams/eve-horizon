import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  API_URL,
  GOTRUE_URL,
  SSO_ORIGIN,
  cookieLine,
  gotrueAccessToken,
  loadSso,
  send,
  stubUpstream,
  type UpstreamCall,
} from './helpers.js';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const ACCESS = gotrueAccessToken('person@example.com');
const DASHBOARD = 'https://dashboard.eve.example';
const APP = 'https://shop.apps.eve.example';

/**
 * GoTrue and the Eve API. The API's origin check answers with `profile` and
 * whether the origin is one it allows; its session route mints `eve-token`.
 */
function upstream(options: { profile?: string; allowed?: boolean; sessionStatus?: number } = {}) {
  return stubUpstream({
    [`POST ${GOTRUE_URL}/token?grant_type=refresh_token`]: () =>
      Response.json({ access_token: ACCESS, refresh_token: 'rt-rotated' }),
    [`POST ${GOTRUE_URL}/logout`]: () => new Response(null, { status: 204 }),
    [`POST ${API_URL}/auth/sso/check-origin`]: () =>
      Response.json({ profile: options.profile ?? 'strict', allowed: options.allowed ?? true }),
    [`POST ${API_URL}/auth/sso/session`]: () =>
      options.sessionStatus && options.sessionStatus !== 200
        ? Response.json({ message: 'refused' }, { status: options.sessionStatus })
        : Response.json({ access_token: 'eve-token', token_type: 'bearer', expires_at: 1, user_id: 'user_1' }),
    [`POST ${API_URL}/auth/exchange`]: () =>
      Response.json({ access_token: 'eve-token', token_type: 'bearer', expires_at: 1, user_id: 'user_1' }),
  });
}

const refreshCalls = (calls: UpstreamCall[]) => calls.filter((c) => c.url.startsWith(`${GOTRUE_URL}/token`));
const SESSION = { cookie: '__Host-eve_sso_rt=rt-current' };

describe('GET /session', () => {
  it('reads only the __Host- refresh cookie: a planted parent-domain eve_sso_rt is ignored', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const res = await send(app, { path: '/session', headers: { origin: DASHBOARD, cookie: 'eve_sso_rt=planted' } });
    expect(res.status).toBe(401);
    expect(refreshCalls(calls)).toEqual([]);
  });

  it('refreshes from the __Host- cookie, rotates it and returns the token the API issued', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const res = await send(app, { path: '/session', headers: { origin: DASHBOARD, ...SESSION } });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.text)).toMatchObject({ access_token: 'eve-token', user: { id: 'user_1', email: 'person@example.com' } });
    expect(JSON.parse(refreshCalls(calls)[0]?.body ?? '{}')).toEqual({ refresh_token: 'rt-current' });
    expect(cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=rt-rotated'))).toBeDefined();
    expect(res.headers['access-control-allow-origin']).toBe(DASHBOARD);
  });

  it('asks the API about the origin and project, then for a token for them', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    await send(app, { path: '/session?project_id=proj_shop', headers: { origin: APP, ...SESSION } });

    const check = calls.find((c) => c.url === `${API_URL}/auth/sso/check-origin`);
    expect(JSON.parse(check?.body ?? '{}')).toEqual({ origin: APP, project_id: 'proj_shop', purpose: 'session' });
    const session = calls.find((c) => c.url === `${API_URL}/auth/sso/session`);
    expect(session?.headers.authorization).toBe(`Bearer ${ACCESS}`);
    expect(JSON.parse(session?.body ?? '{}')).toEqual({ origin: APP, project_id: 'proj_shop' });
  });

  it('keeps tokens out of every URL it calls', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    await send(app, { path: '/session?project_id=proj_shop', headers: { origin: APP, ...SESSION } });
    for (const call of calls) {
      expect(call.url).not.toContain('rt-current');
      expect(call.url).not.toContain(ACCESS);
    }
  });

  describe('under the strict instance profile', () => {
    it('refuses a request with no Origin, before touching the session', async () => {
      const app = await loadSso();
      const { calls } = upstream({ profile: 'strict', allowed: false });
      const res = await send(app, { path: '/session', headers: SESSION });
      expect(res.status).toBe(403);
      expect(refreshCalls(calls)).toEqual([]);
      expect(res.cookies).toEqual([]);
    });

    it('refuses an origin the API does not allow, with no CORS headers, even on the cluster domain', async () => {
      const app = await loadSso();
      const { calls } = upstream({ profile: 'strict', allowed: false });
      const res = await send(app, { path: '/session?project_id=proj_shop', headers: { origin: 'https://other.eve.example', ...SESSION } });
      expect(res.status).toBe(403);
      expect(res.headers['access-control-allow-origin']).toBeUndefined();
      expect(refreshCalls(calls)).toEqual([]);
    });

    it('passes on the refusal when the API will not issue a token for this visitor, keeping the session', async () => {
      const app = await loadSso();
      upstream({ profile: 'strict', allowed: true, sessionStatus: 403 });
      const res = await send(app, { path: '/session?project_id=proj_shop', headers: { origin: APP, ...SESSION } });
      expect(res.status).toBe(403);
      expect(cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=rt-rotated'))).toBeDefined();
    });
  });

  describe('under audit', () => {
    it('keeps today\'s origin rules: a cluster origin is served', async () => {
      const app = await loadSso();
      upstream({ profile: 'audit', allowed: false });
      const res = await send(app, { path: '/session', headers: { origin: 'https://other.eve.example', ...SESSION } });
      expect(res.status).toBe(200);
      expect(res.headers['access-control-allow-origin']).toBe('https://other.eve.example');
    });
  });
});

describe('POST /logout', () => {
  it('refreshes once and ends that GoTrue session only (scope=local), then clears the cookies', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const res = await send(app, { method: 'POST', path: '/logout', headers: { origin: DASHBOARD, ...SESSION } });

    expect(res.status).toBe(200);
    expect(refreshCalls(calls).length).toBe(1);
    const logout = calls.find((c) => c.url.startsWith(`${GOTRUE_URL}/logout`));
    expect(logout).toBeDefined();
    expect(new URL(logout!.url).searchParams.get('scope')).toBe('local');
    expect(logout!.headers.authorization).toBe(`Bearer ${ACCESS}`);
    expect(cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=;'))).toBeDefined();
  });

  it('clears the cookies even when GoTrue cannot be reached', async () => {
    const app = await loadSso();
    stubUpstream({
      [`POST ${API_URL}/auth/sso/check-origin`]: () => Response.json({ profile: 'strict', allowed: true }),
      [`POST ${GOTRUE_URL}/token`]: () => new Response('down', { status: 503 }),
    });
    const res = await send(app, { method: 'POST', path: '/logout', headers: { origin: SSO_ORIGIN, ...SESSION } });
    expect(res.status).toBe(200);
    expect(cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=;'))).toBeDefined();
  });

  it('under strict, refuses an origin the API does not allow and leaves the session alone', async () => {
    const app = await loadSso();
    const { calls } = upstream({ profile: 'strict', allowed: false });
    const res = await send(app, { method: 'POST', path: '/logout', headers: { origin: 'https://evil.eve.example', ...SESSION } });
    expect(res.status).toBe(403);
    expect(calls.some((c) => c.url.startsWith(`${GOTRUE_URL}/`))).toBe(false);
    expect(res.cookies).toEqual([]);
  });
});
