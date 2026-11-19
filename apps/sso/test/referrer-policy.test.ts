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
  type TestResponse,
} from './helpers.js';

/**
 * A browser sends `Origin: null` on a form POST (a navigation) from a page
 * whose referrer policy is no-referrer (Fetch standard, "append a request
 * Origin header"). SSO pages that post a form to the SSO must therefore keep
 * a policy that sends the origin; no-referrer stays only on pages that post
 * nowhere.
 */

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

/** The page's referrer policy: a <meta name="referrer"> wins over the header. */
function referrerPolicy(res: TestResponse): string {
  const meta = [...res.text.matchAll(/<meta name="referrer" content="([^"]+)">/g)].at(-1)?.[1];
  return (meta ?? String(res.headers['referrer-policy'] ?? '')).trim().toLowerCase();
}

/** The Origin header a browser sends on a same-origin form POST from this page. */
function formPostOrigin(res: TestResponse): string {
  return referrerPolicy(res) === 'no-referrer' ? 'null' : SSO_ORIGIN;
}

const stateFrom = (cookies: string[]) => cookieLine(cookies, '__Host-eve_sso_state')?.split(';')[0];
const WRAP = 'mlw_0123456789abcdefghjkmnpqrs';

function upstream() {
  return stubUpstream({
    [`POST ${API_URL}/auth/exchange`]: () =>
      Response.json({ access_token: 'eve-token', token_type: 'bearer', expires_at: 1, user_id: 'user_1' }),
    [`GET ${API_URL}/auth/app-context`]: () => new Response('not found', { status: 404 }),
    [`POST ${API_URL}/internal/auth/magic-link-wrap/inspect`]: () =>
      Response.json({ found: true, kind: 'magic_link', project_id: null, org_id: null, redirect_to: null, expires_at: '2099-01-01', expired: false, consumed: false, get_count: 1 }),
    [`POST ${API_URL}/internal/auth/magic-link-wrap/consume`]: () =>
      Response.json({ status: 'ok', gotrue_action_link: 'https://auth.eve.example/verify?token=t&type=magiclink&redirect_to=https%3A%2F%2Fsso.eve.example%2F', kind: 'magic_link', project_id: null, org_id: null }),
  });
}

describe('referrer policy on SSO pages that post a form', () => {
  it('the "Continue as" form comes back with the origin a browser sends from that page', async () => {
    const app = await loadSso();
    upstream();
    const ask = await send(app, {
      method: 'POST',
      path: '/callback',
      headers: { origin: SSO_ORIGIN, 'content-type': 'application/x-www-form-urlencoded' },
      body: form({ access_token: gotrueAccessToken('person@example.com'), refresh_token: 'rt-1', type: 'magiclink' }),
    });
    expect(ask.text).toContain('Continue as');
    const confirm = /name="confirm" value="([^"]+)"/.exec(ask.text)?.[1];
    const res = await send(app, {
      method: 'POST',
      path: '/callback',
      headers: { origin: formPostOrigin(ask), 'content-type': 'application/x-www-form-urlencoded', cookie: stateFrom(ask.cookies)! },
      body: form({ access_token: gotrueAccessToken('person@example.com'), refresh_token: 'rt-1', type: 'magiclink', confirm: confirm! }),
    });
    expect(res.status).toBe(302);
    expect(cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=rt-1'))).toBeDefined();
  });

  it('the sign-in link page (GET /m/:wrap) keeps the origin on its form POST', async () => {
    const app = await loadSso();
    upstream();
    const page = await send(app, { path: `/m/${WRAP}` });
    expect(page.status).toBe(200);
    expect(page.text).toContain(`action="/m/${WRAP}"`);
    expect(formPostOrigin(page)).toBe(SSO_ORIGIN);
  });

  it('pages that post a form never use no-referrer', async () => {
    const app = await loadSso();
    upstream();
    const pages = [
      await send(app, { path: '/login' }),
      await send(app, { path: '/' }),
      await send(app, { path: '/callback' }),
      await send(app, { path: `/m/${WRAP}` }),
    ];
    for (const page of pages) expect(referrerPolicy(page)).not.toBe('no-referrer');
  });

  it('an unusable sign-in link page, which posts nowhere, keeps no-referrer', async () => {
    const app = await loadSso();
    upstream();
    const page = await send(app, { path: '/m/not-a-wrap-token' });
    expect(page.status).toBe(410);
    expect(page.text).not.toContain('<form');
    expect(referrerPolicy(page)).toBe('no-referrer');
  });
});
