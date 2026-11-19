import vm from 'node:vm';
import { afterEach, describe, expect, it, vi } from 'vitest';

/**
 * The SSO pages that receive GoTrue tokens (in the URL fragment, or from the
 * password sign-in) must hand them to /callback in a POST body, never in a
 * URL. Each page's script runs here against a minimal browser stand-in that
 * records navigations and form submissions.
 */

afterEach(() => {
  vi.unstubAllEnvs();
});

interface Recorded {
  navigations: string[];
  submissions: Array<{ method: string; action: string; fields: Record<string, string> }>;
}

function runPage(html: string, location: { hash?: string; search?: string; pathname?: string }) {
  const recorded: Recorded = { navigations: [], submissions: [] };
  const scripts = [...html.matchAll(/<script\b[^>]*>([\s\S]*?)<\/script>/g)].map((m) => m[1]);

  const makeElement = () => {
    const children: Array<{ name: string; value: string }> = [];
    const element: Record<string, unknown> = {
      method: 'GET',
      action: '',
      type: '',
      name: '',
      value: '',
      style: {},
      classList: { add() {}, remove() {}, toggle() {} },
      appendChild(child: { name: string; value: string }) { children.push(child); return child; },
      setAttribute(key: string, value: string) { element[key] = value; },
      addEventListener() {},
      submit() {
        recorded.submissions.push({
          method: String(element.method).toUpperCase(),
          action: String(element.action),
          fields: Object.fromEntries(children.map((c) => [c.name, c.value])),
        });
      },
    };
    return element;
  };

  const windowLocation = {
    hash: location.hash ?? '',
    search: location.search ?? '',
    pathname: location.pathname ?? '/',
    replace(url: string) { recorded.navigations.push(url); },
    assign(url: string) { recorded.navigations.push(url); },
    set href(url: string) { recorded.navigations.push(url); },
    get href() { return `https://sso.eve.example${this.pathname}${this.search}${this.hash}`; },
  };

  const context: Record<string, unknown> = {
    URLSearchParams,
    JSON,
    encodeURIComponent,
    console,
    location: windowLocation,
    history: { replaceState() {} },
    document: {
      createElement: makeElement,
      getElementById: () => makeElement(),
      body: { appendChild() {} },
      cookie: '',
    },
    fetch: async () => ({ ok: true, json: async () => ({}) }),
  };
  context.window = context;
  vm.createContext(context);
  for (const script of scripts) vm.runInContext(script, context);
  return { recorded, context };
}

function expectTokensPosted(recorded: Recorded, accessToken: string): void {
  for (const url of recorded.navigations) {
    expect(url).not.toContain(accessToken);
    expect(url).not.toContain('refresh_token');
  }
  expect(recorded.submissions).toEqual([
    expect.objectContaining({
      method: 'POST',
      action: '/callback',
      fields: expect.objectContaining({ access_token: accessToken, refresh_token: 'rt-1' }),
    }),
  ]);
}

const HASH = '#access_token=at-1&refresh_token=rt-1&type=magiclink&expires_in=3600';

async function views() {
  vi.resetModules();
  vi.stubEnv('EVE_DEFAULT_DOMAIN', 'eve.example');
  vi.stubEnv('EVE_SSO_SECURE_COOKIES', 'true');
  return {
    extractor: (await import('../src/views/callback-extractor.js')).callbackExtractorHtml,
    login: (await import('../src/views/login.js')).loginPageHtml,
    landing: (await import('../src/views/landing.js')).landingPageHtml,
  };
}

describe('pages that hand tokens to /callback', () => {
  it('the /callback fragment reader posts the tokens', async () => {
    const { extractor } = await views();
    const { recorded } = runPage(extractor(), {
      pathname: '/callback',
      hash: HASH,
      search: '?redirect_to=https%3A%2F%2Fdashboard.eve.example%2F',
    });
    expectTokensPosted(recorded, 'at-1');
    expect(recorded.submissions[0]?.fields.redirect_to).toBe('https://dashboard.eve.example/');
  });

  it('the fragment reader still sends a GoTrue error to /callback without tokens', async () => {
    const { extractor } = await views();
    const { recorded } = runPage(extractor(), { pathname: '/callback', hash: '#error=access_denied&error_code=otp_expired' });
    expect(recorded.submissions).toEqual([]);
    expect(recorded.navigations).toHaveLength(1);
    expect(recorded.navigations[0]).toContain('error_code=otp_expired');
  });

  it('the landing page posts the tokens from its fragment', async () => {
    const { landing } = await views();
    const html = landing({ redirectTo: 'https://dashboard.eve.example/', projectId: '', signedIn: false, continueHref: '/login' });
    const { recorded } = runPage(html, { pathname: '/', hash: HASH });
    expectTokensPosted(recorded, 'at-1');
  });

  it('the login page posts the tokens from its fragment', async () => {
    const { login } = await views();
    const { recorded } = runPage(login('https://dashboard.eve.example/', 'signin'), { pathname: '/login', hash: HASH });
    expectTokensPosted(recorded, 'at-1');
  });

  it('the login page posts the tokens from a password sign-in', async () => {
    const { login } = await views();
    const { recorded, context } = runPage(login('https://dashboard.eve.example/', 'signin'), { pathname: '/login' });
    vm.runInContext("goToCallback('at-2', 'rt-1')", context);
    expectTokensPosted(recorded, 'at-2');
  });
});
