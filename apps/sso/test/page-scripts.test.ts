import vm from 'node:vm';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { API_URL, SSO_ORIGIN, loadSso, send, stubUpstream } from './helpers.js';

/**
 * Server values reach SSO pages only escaped for where they land: as JSON
 * that cannot end its <script> in inline scripts, HTML-escaped in markup and
 * attributes, and only http(s) addresses the SSO may send people to as
 * redirect targets. Every inline script carries the response's CSP nonce and
 * no page uses inline event-handler attributes.
 */

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

const SCRIPT_RE = /<script\b([^>]*)>([\s\S]*?)<\/script>/g;

/** Run a page's inline scripts against a minimal browser stand-in. */
function runScripts(html: string): { context: vm.Context; alerts: unknown[]; navigations: string[] } {
  const alerts: unknown[] = [];
  const navigations: string[] = [];
  const element = () => ({
    addEventListener() {},
    appendChild() {},
    classList: { add() {}, remove() {}, toggle() {} },
    style: {},
    textContent: '',
    value: '',
  });
  const context: Record<string, unknown> = {
    URLSearchParams,
    JSON,
    encodeURIComponent,
    console,
    alert: (value: unknown) => alerts.push(value),
    location: {
      hash: '',
      search: '',
      pathname: '/',
      replace: (url: string) => navigations.push(url),
      set href(url: string) { navigations.push(url); },
    },
    history: { replaceState() {} },
    document: { getElementById: element, createElement: element, body: element(), cookie: '', domain: 'sso.eve.example' },
    fetch: async () => ({ ok: true, json: async () => ({}) }),
  };
  context.window = context;
  vm.createContext(context);
  for (const [, , code] of html.matchAll(SCRIPT_RE)) vm.runInContext(code ?? '', context);
  return { context, alerts, navigations };
}

const valueOf = (context: vm.Context, name: string) => vm.runInContext(name, context) as unknown;

function appContext(allowedOrigins: string[], branding: Record<string, unknown> = {}) {
  return stubUpstream({
    [`GET ${API_URL}/auth/app-context`]: () =>
      Response.json({ project_id: 'proj_app', auth: { allowed_redirect_origins: allowedOrigins }, branding }),
    [`POST ${API_URL}/internal/auth/magic-link-wrap/inspect`]: () =>
      Response.json({ found: true, kind: 'magic_link', project_id: 'proj_app', org_id: null, redirect_to: null, expires_at: '2099-01-01', expired: false, consumed: false, get_count: 1 }),
  });
}

const BREAKOUT = "';alert(document.domain)//";
const SCRIPT_BREAKOUT = '</script><script>alert(document.domain)</script>';

describe('the set-password page', () => {
  it('keeps a quote in redirect_to inside its string', async () => {
    const app = await loadSso();
    appContext([]);
    const res = await send(app, { path: `/set-password?redirect_to=${encodeURIComponent(BREAKOUT)}` });
    expect(res.status).toBe(200);
    const { alerts } = runScripts(res.text);
    expect(alerts).toEqual([]);
  });

  it('keeps a cluster https redirect_to', async () => {
    const app = await loadSso();
    appContext([]);
    const res = await send(app, { path: `/set-password?redirect_to=${encodeURIComponent('https://dashboard.eve.example/x')}` });
    expect(valueOf(runScripts(res.text).context, 'REDIRECT_TO')).toBe('https://dashboard.eve.example/x');
  });

  it.each([
    ['another site', 'https://evil.example/'],
    ['a javascript: URL on a cluster host', 'javascript://sso.eve.example/%0aalert(document.domain)'],
    ['a quote breakout', BREAKOUT],
  ])('drops a redirect_to that is %s', async (_label, target) => {
    const app = await loadSso();
    appContext([]);
    const res = await send(app, { path: `/set-password?redirect_to=${encodeURIComponent(target)}` });
    expect(valueOf(runScripts(res.text).context, 'REDIRECT_TO')).toBe('');
  });

  it("keeps a redirect_to that the project's allowed origins name", async () => {
    const app = await loadSso();
    appContext(['https://app.customer.example']);
    const res = await send(app, {
      path: `/set-password?project_id=proj_app&redirect_to=${encodeURIComponent('https://app.customer.example/home')}`,
    });
    expect(valueOf(runScripts(res.text).context, 'REDIRECT_TO')).toBe('https://app.customer.example/home');
  });
});

describe('server values in the login and landing pages', () => {
  it.each([
    ['/login', '/login'],
    ['/ (landing)', '/'],
  ])('%s keeps a redirect_to that closes a script inside its string', async (_label, path) => {
    const app = await loadSso();
    appContext([]);
    const res = await send(app, { path: `${path}?redirect_to=${encodeURIComponent(SCRIPT_BREAKOUT)}` });
    expect([...res.text.matchAll(SCRIPT_RE)]).toHaveLength(1);
    const { context, alerts } = runScripts(res.text);
    expect(alerts).toEqual([]);
    expect(valueOf(context, 'REDIRECT_TO')).toBe(SCRIPT_BREAKOUT);
  });

  it('jsString escapes characters that could end a script or a string', async () => {
    vi.resetModules();
    const { jsString } = await import('../src/views/chrome.js');
    const encoded = jsString("<>&'\u2028\u2029");
    expect(encoded).not.toMatch(/[<>&'\u2028\u2029]/);
    expect(JSON.parse(encoded)).toBe("<>&'\u2028\u2029");
  });

  it('the landing page links only to an http(s) allowed origin', async () => {
    const app = await loadSso();
    appContext(['javascript:alert(document.domain)']);
    const res = await send(app, { path: '/?project_id=proj_app', headers: { cookie: '__Host-eve_sso_rt=rt-1' } });
    expect(res.text).not.toContain('javascript:');
  });

  it.each([
    ['/login?project_id=proj_app'],
    ['/m/mlw_0123456789abcdefghjkmnpqrs'],
  ])('%s ignores a branding colour that is not #rrggbb', async (path) => {
    const app = await loadSso();
    appContext([], { primary_color: 'red;}</style><script>alert(document.domain)</script>' });
    const res = await send(app, { path });
    expect(res.status).toBe(200);
    expect(res.text).not.toContain('alert(document.domain)');
  });
});

describe('content security policy', () => {
  it.each([
    ['/login'],
    ['/'],
    ['/set-password'],
    ['/callback'],
  ])('%s sets a script nonce, carries it on every script and has no inline handlers', async (path) => {
    const app = await loadSso();
    appContext([]);
    const res = await send(app, { path, headers: { origin: SSO_ORIGIN } });
    const csp = String(res.headers['content-security-policy'] ?? '');
    const nonce = /script-src 'nonce-([A-Za-z0-9+/=]+)'/.exec(csp)?.[1];
    expect(nonce).toBeTruthy();
    expect(csp).toContain("object-src 'none'");
    expect(csp).toContain("base-uri 'none'");
    const scripts = [...res.text.matchAll(SCRIPT_RE)];
    expect(scripts.length).toBeGreaterThan(0);
    for (const [, attrs] of scripts) expect(attrs).toContain(`nonce="${nonce}"`);
    expect(res.text).not.toMatch(/\son[a-z]+="/i);
  });

  it('uses a new nonce for each response', async () => {
    const app = await loadSso();
    appContext([]);
    const first = await send(app, { path: '/login' });
    const second = await send(app, { path: '/login' });
    expect(first.headers['content-security-policy']).not.toBe(second.headers['content-security-policy']);
  });
});
