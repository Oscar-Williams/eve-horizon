import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  API_URL,
  SSO_ORIGIN,
  cookieLine,
  form,
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
const DASHBOARD = 'https://dashboard.eve.example/';
const FLOW_STATE = '__Host-eve_sso_state=flow.started-at-login';

function upstream() {
  return stubUpstream({
    [`POST ${API_URL}/auth/exchange`]: () =>
      Response.json({ access_token: 'eve-token', token_type: 'bearer', expires_at: 1, user_id: 'user_1' }),
    [`GET ${API_URL}/auth/app-context`]: () => new Response('not found', { status: 404 }),
    [`POST ${API_URL}/internal/auth/magic-link-wrap/consume`]: () =>
      Response.json({ status: 'ok', gotrue_action_link: 'https://auth.eve.example/verify?token=t', kind: 'magic_link', project_id: null, org_id: null }),
  });
}

const exchanges = (calls: UpstreamCall[]) => calls.filter((c) => c.url === `${API_URL}/auth/exchange`);
const sessionCookie = (cookies: string[]) =>
  cookies.find((l) => /^(__Host-)?eve_sso_rt=[^;]+/.test(l) && !/^(__Host-)?eve_sso_rt=;/.test(l));

function postCallback(app: Awaited<ReturnType<typeof loadSso>>, fields: Record<string, string>, headers: Record<string, string> = {}) {
  return send(app, {
    method: 'POST',
    path: '/callback',
    headers: { origin: SSO_ORIGIN, 'content-type': 'application/x-www-form-urlencoded', ...headers },
    body: form(fields),
  });
}

const tokens = { access_token: ACCESS, refresh_token: 'rt-1', type: 'magiclink', redirect_to: DASHBOARD };

describe('GET /callback', () => {
  it('refuses tokens in the query string and sets no session', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const res = await send(app, {
      path: `/callback?access_token=${encodeURIComponent(ACCESS)}&refresh_token=rt-1&redirect_to=${encodeURIComponent(DASHBOARD)}`,
      headers: { cookie: FLOW_STATE },
    });
    expect(sessionCookie(res.cookies)).toBeUndefined();
    expect(exchanges(calls)).toEqual([]);
    expect(res.headers.location ?? '').not.toContain('rt-1');
  });

  it('still serves the page that reads tokens from the URL fragment', async () => {
    const app = await loadSso();
    upstream();
    const res = await send(app, { path: '/callback' });
    expect(res.status).toBe(200);
    expect(res.text).toContain('Authenticating');
  });
});

describe('POST /callback', () => {
  it('sets the session and returns to the target when the SSO started the flow', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const res = await postCallback(app, tokens, { cookie: FLOW_STATE });
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe(DASHBOARD);
    expect(cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=rt-1'))).toBeDefined();
    expect(exchanges(calls).length).toBe(1);
    expect(cookieLine(res.cookies, '__Host-eve_sso_state', (l) => l.startsWith('__Host-eve_sso_state=;'))).toBeDefined();
  });

  it('refuses a POST from another origin', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const res = await postCallback(app, tokens, { cookie: FLOW_STATE, origin: 'https://evil.example' });
    expect(res.status).toBe(403);
    expect(sessionCookie(res.cookies)).toBeUndefined();
    expect(exchanges(calls)).toEqual([]);
  });

  it('refuses a POST with no Origin', async () => {
    const app = await loadSso();
    upstream();
    const res = await send(app, {
      method: 'POST',
      path: '/callback',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie: FLOW_STATE },
      body: form(tokens),
    });
    expect(res.status).toBe(403);
    expect(sessionCookie(res.cookies)).toBeUndefined();
  });

  describe('with no state cookie (an invite, or a link opened in another browser)', () => {
    it('asks "Continue as" the token\'s email instead of setting the session', async () => {
      const app = await loadSso();
      const { calls } = upstream();
      const res = await postCallback(app, tokens);
      expect(res.status).toBe(200);
      expect(res.text).toContain('Continue as');
      expect(res.text).toContain('person@example.com');
      expect(sessionCookie(res.cookies)).toBeUndefined();
      expect(exchanges(calls)).toEqual([]);
    });

    it('sets the session once the person confirms on that page', async () => {
      const app = await loadSso();
      upstream();
      const ask = await postCallback(app, tokens);
      const state = cookieLine(ask.cookies, '__Host-eve_sso_state')?.split(';')[0] ?? '';
      const confirm = /name="confirm" value="([^"]+)"/.exec(ask.text)?.[1] ?? '';
      expect(state).not.toBe('');
      expect(confirm).not.toBe('');

      const res = await postCallback(app, { ...tokens, confirm }, { cookie: state });
      expect(res.status).toBe(302);
      expect(cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=rt-1'))).toBeDefined();
    });

    it('asks again when the confirmation does not match the cookie', async () => {
      const app = await loadSso();
      upstream();
      const ask = await postCallback(app, tokens);
      const state = cookieLine(ask.cookies, '__Host-eve_sso_state')?.split(';')[0] ?? '';

      const res = await postCallback(app, { ...tokens, confirm: 'guessed' }, { cookie: state });
      expect(res.status).toBe(200);
      expect(res.text).toContain('Continue as');
      expect(sessionCookie(res.cookies)).toBeUndefined();
    });

    it('does not let a pending confirmation stand in for a started flow', async () => {
      const app = await loadSso();
      upstream();
      const ask = await postCallback(app, tokens);
      const state = cookieLine(ask.cookies, '__Host-eve_sso_state')?.split(';')[0] ?? '';

      const res = await postCallback(app, tokens, { cookie: state });
      expect(res.status).toBe(200);
      expect(sessionCookie(res.cookies)).toBeUndefined();
    });
  });
});

describe('flows the SSO starts', () => {
  it('GET /login sets a short-lived host-only state cookie', async () => {
    const app = await loadSso();
    upstream();
    const res = await send(app, { path: `/login?redirect_to=${encodeURIComponent(DASHBOARD)}` });
    const line = cookieLine(res.cookies, '__Host-eve_sso_state');
    expect(line).toBeDefined();
    expect(line).toMatch(/;\s*Secure/);
    expect(line).toMatch(/;\s*HttpOnly/);
    expect(line).not.toMatch(/Domain=/i);
    const maxAge = Number(/Max-Age=(\d+)/.exec(line!)?.[1]);
    expect(maxAge).toBeGreaterThan(0);
    expect(maxAge).toBeLessThanOrEqual(3600);
  });

  it('confirming a sign-in link (POST /m/:wrap) sets the state cookie', async () => {
    const app = await loadSso();
    upstream();
    const { signWrapCsrf } = await import('../src/security.js');
    const wrap = 'mlw_0123456789abcdefghjkmnpqrs';
    const res = await send(app, {
      method: 'POST',
      path: `/m/${wrap}`,
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: SSO_ORIGIN },
      body: form({ csrf: signWrapCsrf(wrap) }),
    });
    expect(res.status).toBe(302);
    expect(cookieLine(res.cookies, '__Host-eve_sso_state')).toBeDefined();
  });
});
