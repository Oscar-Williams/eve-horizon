import { afterEach, describe, expect, it, vi } from 'vitest';
import { GOTRUE_URL, SSO_ORIGIN, loadSso, send, stubUpstream } from './helpers.js';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const DASHBOARD = 'https://dashboard.eve.example/';

function requestLink(app: Awaited<ReturnType<typeof loadSso>>, body: Record<string, unknown>) {
  return send(app, {
    method: 'POST',
    path: '/auth/magiclink',
    headers: { 'content-type': 'application/json', origin: SSO_ORIGIN },
    body: JSON.stringify(body),
  });
}

describe('POST /auth/magiclink with no project (the Eve dashboard)', () => {
  it('asks GoTrue to return through the SSO, carrying the dashboard address, as a query parameter', async () => {
    const app = await loadSso();
    const upstream = stubUpstream({ [`POST ${GOTRUE_URL}/magiclink`]: () => Response.json({}) });

    const res = await requestLink(app, { email: 'person@example.com', redirect_to: DASHBOARD });

    expect(res.status).toBe(200);
    const call = upstream.calls.find((c) => c.url.startsWith(`${GOTRUE_URL}/magiclink`));
    expect(call).toBeDefined();
    const redirect = new URL(call!.url).searchParams.get('redirect_to');
    expect(redirect).toBe(`${SSO_ORIGIN}/?redirect_to=${encodeURIComponent(DASHBOARD)}`);
    expect(JSON.parse(call!.body ?? '{}')).toEqual({ email: 'person@example.com' });
  });

  it('returns through the SSO alone when the requested address is outside the cluster', async () => {
    const app = await loadSso();
    const upstream = stubUpstream({ [`POST ${GOTRUE_URL}/magiclink`]: () => Response.json({}) });

    await requestLink(app, { email: 'person@example.com', redirect_to: 'https://evil.example/phish' });

    const call = upstream.calls.find((c) => c.url.startsWith(`${GOTRUE_URL}/magiclink`));
    expect(call).toBeDefined();
    expect(new URL(call!.url).searchParams.get('redirect_to')).toBe(`${SSO_ORIGIN}/`);
  });

  it('gives the same reply whether or not the email has an account', async () => {
    const app = await loadSso();
    stubUpstream({
      [`POST ${GOTRUE_URL}/magiclink`]: (call) => {
        const { email } = JSON.parse(call.body ?? '{}') as { email?: string };
        return email === 'known@example.com'
          ? Response.json({})
          : Response.json({ code: 422, error_code: 'otp_disabled', msg: 'Signups not allowed for otp' }, { status: 422 });
      },
    });

    const known = await requestLink(app, { email: 'known@example.com', redirect_to: DASHBOARD });
    const unknown = await requestLink(app, { email: 'nobody@example.com', redirect_to: DASHBOARD });

    expect(unknown.status).toBe(known.status);
    expect(unknown.text).toBe(known.text);
    expect(known.status).toBe(200);
  });

  it('gives the same reply when GoTrue limits the sending rate', async () => {
    const app = await loadSso();
    stubUpstream({
      [`POST ${GOTRUE_URL}/magiclink`]: () =>
        Response.json({ code: 429, error_code: 'over_email_send_rate_limit', msg: 'rate limited' }, { status: 429 }),
    });

    const res = await requestLink(app, { email: 'known@example.com', redirect_to: DASHBOARD });

    expect(res.status).toBe(200);
    expect(res.text).not.toContain('rate');
  });
});
