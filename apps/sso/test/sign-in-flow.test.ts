import vm from 'node:vm';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  API_URL,
  GOTRUE_URL,
  SSO_ORIGIN,
  cookieLine,
  form,
  gotrueAccessToken,
  loadSso,
  send,
  stubUpstream,
  type TestResponse,
  type UpstreamCall,
} from './helpers.js';

/**
 * A sign-in sets a session at once only when the tokens come back with the
 * flow nonce this browser holds in its state cookie: the nonce travels
 * through GoTrue's redirect_to (`?flow=<nonce>`) and the SSO's page posts it
 * with the tokens. Tokens without it get "Continue as". The sign-in link page
 * takes its POST only from the SSO's own origin with a CSRF value bound to
 * this browser, and sign-out takes a POST only with an Origin.
 */

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

type App = Awaited<ReturnType<typeof loadSso>>;

const WRAP = 'mlw_0123456789abcdefghjkmnpqrs';
const DASHBOARD = 'https://dashboard.eve.example/';
const ATTACKER = gotrueAccessToken('attacker@example.com');
const PERSON = gotrueAccessToken('person@example.com');

function upstream(actionLink = 'https://auth.eve.example/verify?token=t&type=magiclink&redirect_to=https%3A%2F%2Fsso.eve.example%2F%3Fproject_id%3Dproj_app') {
  return stubUpstream({
    [`POST ${API_URL}/auth/exchange`]: () =>
      Response.json({ access_token: 'eve-token', token_type: 'bearer', expires_at: 1, user_id: 'user_1' }),
    [`GET ${API_URL}/auth/app-context`]: () => new Response('not found', { status: 404 }),
    [`POST ${API_URL}/internal/auth/magic-link-wrap/inspect`]: () =>
      Response.json({ found: true, kind: 'magic_link', project_id: 'proj_app', org_id: null, redirect_to: null, expires_at: '2099-01-01', expired: false, consumed: false, get_count: 1 }),
    [`POST ${API_URL}/internal/auth/magic-link-wrap/consume`]: () =>
      Response.json({ status: 'ok', gotrue_action_link: actionLink, kind: 'magic_link', project_id: 'proj_app', org_id: null }),
    [`POST ${API_URL}/auth/sso/check-origin`]: (call) => {
      const { origin } = JSON.parse(call.body ?? '{}') as { origin?: string | null };
      return Response.json({ profile: 'audit', allowed: Boolean(origin) });
    },
    [`POST ${GOTRUE_URL}/token`]: () => Response.json({ access_token: PERSON, refresh_token: 'rt-2' }),
    [`POST ${GOTRUE_URL}/logout`]: () => new Response(null, { status: 204 }),
    [`POST ${GOTRUE_URL}/magiclink`]: () => Response.json({}),
  });
}

const stateCookie = (res: TestResponse) => cookieLine(res.cookies, '__Host-eve_sso_state')?.split(';')[0];
const flowOf = (cookie: string | undefined) => /^__Host-eve_sso_state=flow\.(.+)$/.exec(cookie ?? '')?.[1];
const sessionSet = (res: TestResponse) =>
  res.cookies.some((l) => /^__Host-eve_sso_rt=[^;]+/.test(l) && !l.startsWith('__Host-eve_sso_rt=;'));
const exchanges = (calls: UpstreamCall[]) => calls.filter((c) => c.url === `${API_URL}/auth/exchange`);

/** Run a page's scripts with this URL and return the form it posts to /callback. */
function postedByPage(html: string, location: { pathname: string; search?: string; hash?: string }, after?: string) {
  const submissions: Array<Record<string, string>> = [];
  const element = () => {
    const children: Array<{ name: string; value: string }> = [];
    const el: Record<string, unknown> = {
      addEventListener() {},
      appendChild(child: { name: string; value: string }) { children.push(child); return child; },
      classList: { add() {}, remove() {}, toggle() {} },
      style: {},
      submit() { submissions.push(Object.fromEntries(children.map((c) => [c.name, c.value]))); },
    };
    return el;
  };
  const context: Record<string, unknown> = {
    URLSearchParams,
    JSON,
    encodeURIComponent,
    console,
    location: { hash: location.hash ?? '', search: location.search ?? '', pathname: location.pathname, replace() {} },
    history: { replaceState() {} },
    document: { createElement: element, getElementById: element, body: element() },
    fetch: async () => ({ ok: true, json: async () => ({}) }),
  };
  context.window = context;
  vm.createContext(context);
  for (const [, code] of html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)) vm.runInContext(code ?? '', context);
  if (after) vm.runInContext(after, context);
  return submissions;
}

function postCallback(app: App, fields: Record<string, string>, cookie?: string) {
  return send(app, {
    method: 'POST',
    path: '/callback',
    headers: {
      origin: SSO_ORIGIN,
      'content-type': 'application/x-www-form-urlencoded',
      ...(cookie ? { cookie } : {}),
    },
    body: form(fields),
  });
}

const tokenHash = (token: string) => `#access_token=${token}&refresh_token=rt-1&type=magiclink`;

describe('the flow nonce', () => {
  it('a /login link with tokens in its fragment gets "Continue as", not a session', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const page = await send(app, { path: '/login' });
    const cookie = stateCookie(page);
    expect(flowOf(cookie)).toBeTruthy();
    const [posted] = postedByPage(page.text, { pathname: '/login', hash: tokenHash(ATTACKER) });
    expect(posted).toBeDefined();
    const res = await postCallback(app, posted!, cookie);
    expect(res.status).toBe(200);
    expect(res.text).toContain('Continue as');
    expect(sessionSet(res)).toBe(false);
    expect(exchanges(calls)).toEqual([]);
  });

  it('tokens with a flow that is not this browser\'s get "Continue as"', async () => {
    const app = await loadSso();
    upstream();
    const res = await postCallback(
      app,
      { access_token: ATTACKER, refresh_token: 'rt-1', type: 'magiclink', flow: 'someone-elses-flow-nonce' },
      '__Host-eve_sso_state=flow.this-browsers-flow-nonce',
    );
    expect(res.text).toContain('Continue as');
    expect(sessionSet(res)).toBe(false);
  });

  it('a dashboard magic link carries the flow through GoTrue and back to a session', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const login = await send(app, { path: `/login?redirect_to=${encodeURIComponent(DASHBOARD)}` });
    const cookie = stateCookie(login)!;
    const flow = flowOf(cookie)!;

    await send(app, {
      method: 'POST',
      path: '/auth/magiclink',
      headers: { 'content-type': 'application/json', origin: SSO_ORIGIN, cookie },
      body: JSON.stringify({ email: 'person@example.com', redirect_to: DASHBOARD }),
    });
    const gotrue = calls.find((c) => c.url.startsWith(`${GOTRUE_URL}/magiclink`));
    const returnTo = new URL(new URL(gotrue!.url).searchParams.get('redirect_to')!);
    expect(returnTo.origin).toBe(SSO_ORIGIN);
    expect(returnTo.searchParams.get('flow')).toBe(flow);
    expect(returnTo.searchParams.get('redirect_to')).toBe(DASHBOARD);

    const landing = await send(app, { path: `${returnTo.pathname}${returnTo.search}`, headers: { cookie } });
    const [posted] = postedByPage(landing.text, { pathname: returnTo.pathname, search: returnTo.search, hash: tokenHash(PERSON) });
    expect(posted?.flow).toBe(flow);
    const res = await postCallback(app, posted!, cookie);
    expect(res.status).toBe(302);
    expect(res.headers.location).toBe(DASHBOARD);
    expect(sessionSet(res)).toBe(true);
  });

  it('the /callback fragment reader posts the flow from its query', async () => {
    const app = await loadSso();
    upstream();
    const page = await send(app, { path: '/callback?flow=abc123abc123abc123' });
    const [posted] = postedByPage(page.text, { pathname: '/callback', search: '?flow=abc123abc123abc123', hash: tokenHash(PERSON) });
    expect(posted?.flow).toBe('abc123abc123abc123');
  });

  it('a password sign-in on /login posts this browser\'s flow and gets a session', async () => {
    const app = await loadSso();
    upstream();
    const page = await send(app, { path: '/login' });
    const cookie = stateCookie(page)!;
    const [posted] = postedByPage(page.text, { pathname: '/login' }, "goToCallback('at-2', 'rt-2')");
    expect(posted?.flow).toBe(flowOf(cookie));
    const res = await postCallback(app, { ...posted!, access_token: PERSON }, cookie);
    expect(res.status).toBe(302);
    expect(sessionSet(res)).toBe(true);
  });
});

describe('POST /m/:wrap', () => {
  async function openLink(app: App) {
    const page = await send(app, { path: `/m/${WRAP}` });
    const csrf = /name="csrf" value="([^"]+)"/.exec(page.text)?.[1];
    const cookie = stateCookie(page);
    expect(flowOf(cookie), 'GET /m/:wrap starts a flow in this browser').toBeTruthy();
    return { cookie, csrf: csrf! };
  }

  it('refuses a POST from another origin and consumes nothing', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const { cookie, csrf } = await openLink(app);
    const res = await send(app, {
      method: 'POST',
      path: `/m/${WRAP}`,
      headers: { origin: 'https://evil.example', 'content-type': 'application/x-www-form-urlencoded', ...(cookie ? { cookie } : {}) },
      body: form({ csrf }),
    });
    expect(res.status).toBe(403);
    expect(calls.some((c) => c.url.endsWith('/magic-link-wrap/consume'))).toBe(false);
  });

  it("does not take a CSRF value read in another browser", async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const { csrf } = await openLink(app); // the other browser
    const res = await send(app, {
      method: 'POST',
      path: `/m/${WRAP}`,
      headers: { origin: SSO_ORIGIN, 'content-type': 'application/x-www-form-urlencoded', cookie: '__Host-eve_sso_state=flow.this-browsers-flow-nonce' },
      body: form({ csrf }),
    });
    expect(res.headers.location ?? '').not.toContain('auth.eve.example');
    expect(calls.some((c) => c.url.endsWith('/magic-link-wrap/consume'))).toBe(false);
  });

  it('sends the browser to GoTrue with its flow in the return address', async () => {
    const app = await loadSso();
    upstream();
    const { cookie, csrf } = await openLink(app);
    const res = await send(app, {
      method: 'POST',
      path: `/m/${WRAP}`,
      headers: { origin: SSO_ORIGIN, 'content-type': 'application/x-www-form-urlencoded', cookie: cookie! },
      body: form({ csrf }),
    });
    expect(res.status).toBe(302);
    const location = new URL(res.headers.location!);
    expect(location.origin).toBe('https://auth.eve.example');
    const returnTo = new URL(location.searchParams.get('redirect_to')!);
    expect(returnTo.origin).toBe(SSO_ORIGIN);
    expect(returnTo.searchParams.get('project_id')).toBe('proj_app');
    const flow = flowOf(stateCookie(res) ?? cookie);
    expect(flow).toBeTruthy();
    expect(returnTo.searchParams.get('flow')).toBe(flow);
  });

  it('returns a link that pointed past the SSO through the SSO, keeping its target', async () => {
    const app = await loadSso();
    upstream('https://auth.eve.example/verify?token=t&type=invite&redirect_to=https%3A%2F%2Fdashboard.eve.example%2F');
    const { cookie, csrf } = await openLink(app);
    const res = await send(app, {
      method: 'POST',
      path: `/m/${WRAP}`,
      headers: { origin: SSO_ORIGIN, 'content-type': 'application/x-www-form-urlencoded', cookie: cookie! },
      body: form({ csrf }),
    });
    const returnTo = new URL(new URL(res.headers.location!).searchParams.get('redirect_to')!);
    expect(returnTo.origin).toBe(SSO_ORIGIN);
    expect(returnTo.searchParams.get('redirect_to')).toBe(DASHBOARD);
    expect(returnTo.searchParams.get('flow')).toBeTruthy();
  });
});

describe('POST /logout', () => {
  it('refuses a POST with no Origin and leaves the GoTrue session alone', async () => {
    const app = await loadSso();
    const { calls } = upstream();
    const res = await send(app, { method: 'POST', path: '/logout', headers: { cookie: '__Host-eve_sso_rt=rt-1' } });
    expect(res.status).toBe(403);
    expect(calls.some((c) => c.url.startsWith(`${GOTRUE_URL}/logout`))).toBe(false);
  });

  it("takes a POST from the SSO's own origin", async () => {
    const app = await loadSso();
    upstream();
    const res = await send(app, { method: 'POST', path: '/logout', headers: { origin: SSO_ORIGIN, cookie: '__Host-eve_sso_rt=rt-1' } });
    expect(res.status).toBe(200);
  });
});
