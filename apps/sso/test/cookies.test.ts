import { afterEach, describe, expect, it, vi } from 'vitest';
import { cookieLine, loadSso, send } from './helpers.js';

afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
});

/** An app whose routes set or clear the session cookies, on the given cluster. */
async function cookieApp(env: Record<string, string> = {}) {
  await loadSso(env); // stubs the environment and resets modules
  const express = (await import('express')).default;
  const cookies = await import('../src/cookies.js');
  const app = express();
  app.get('/set', (_req, res) => { cookies.setSessionCookies(res, 'rt-new'); res.end(); });
  app.get('/clear', (_req, res) => { cookies.clearSessionCookies(res); res.end(); });
  return app;
}

const hasDomain = (line: string) => /;\s*Domain=/i.test(line);

describe('session cookies on an https cluster', () => {
  it('keeps the refresh token in a host-only __Host- cookie', async () => {
    const res = await send(await cookieApp(), { path: '/set' });
    const line = cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=rt-new'));
    expect(line).toBeDefined();
    expect(line).toMatch(/;\s*Path=\//);
    expect(line).toMatch(/;\s*Secure/);
    expect(line).toMatch(/;\s*HttpOnly/);
    expect(hasDomain(line!)).toBe(false);
  });

  it('clears the old parent-domain refresh cookie', async () => {
    const res = await send(await cookieApp(), { path: '/set' });
    const line = cookieLine(res.cookies, 'eve_sso_rt');
    expect(line).toBeDefined();
    expect(line).toMatch(/^eve_sso_rt=;/);
    expect(line).toMatch(/;\s*Domain=\.eve\.example/i);
    expect(line).toMatch(/;\s*Expires=Thu, 01 Jan 1970/);
    expect(line).toMatch(/;\s*Secure/);
    expect(line).toMatch(/;\s*SameSite=None/i);
  });

  it('keeps the eve_sso hint on the parent domain for apps to read', async () => {
    const res = await send(await cookieApp(), { path: '/set' });
    const line = cookieLine(res.cookies, 'eve_sso', (l) => l.startsWith('eve_sso=1'));
    expect(line).toMatch(/;\s*Domain=\.eve\.example/i);
    expect(line).not.toMatch(/HttpOnly/i);
  });

  it('never sets a refresh token on the parent domain', async () => {
    const res = await send(await cookieApp(), { path: '/set' });
    const withToken = res.cookies.filter((l) => l.includes('rt-new'));
    expect(withToken.length).toBe(1);
    expect(withToken.every((l) => !hasDomain(l))).toBe(true);
  });

  it('clears the __Host- cookie, the old cookie and the hint on sign-out', async () => {
    const res = await send(await cookieApp(), { path: '/clear' });
    expect(cookieLine(res.cookies, '__Host-eve_sso_rt', (l) => l.startsWith('__Host-eve_sso_rt=;') && !hasDomain(l))).toBeDefined();
    expect(cookieLine(res.cookies, 'eve_sso_rt', (l) => /Domain=\.eve\.example/i.test(l))).toBeDefined();
    expect(cookieLine(res.cookies, 'eve_sso', (l) => l.startsWith('eve_sso=;'))).toBeDefined();
  });
});
