import { randomBytes, timingSafeEqual } from 'crypto';
import express from 'express';
import { COOKIE_SAMESITE, EVE_DEFAULT_DOMAIN, SECURE_COOKIES } from './config.js';

/**
 * The GoTrue refresh token lives in a host-only cookie on the SSO's own host.
 * On https it is a `__Host-` cookie: no Domain, Path=/, Secure, so no other
 * host on the domain can set one the SSO would read. Plain http (local
 * clusters) cannot use the prefix and keeps the bare name, host-only.
 */
export const REFRESH_COOKIE = SECURE_COOKIES ? '__Host-eve_sso_rt' : 'eve_sso_rt';

/** The refresh cookie older releases set on the parent domain; every session response clears it. */
const LEGACY_REFRESH_COOKIE = 'eve_sso_rt';

/** Non-secret hint, on the parent domain, that lets apps see a session may exist. */
const HINT_COOKIE = 'eve_sso';

/**
 * Sign-in state: `flow.<nonce>` once /login or a sign-in link starts a flow,
 * or `confirm.<nonce>` while the SSO asks "Continue as ...?". Host-only.
 */
export const STATE_COOKIE = SECURE_COOKIES ? '__Host-eve_sso_state' : 'eve_sso_state';

const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;
const STATE_MAX_AGE_MS = 15 * 60 * 1000;

const parentDomain = () => `.${EVE_DEFAULT_DOMAIN}`;

const refreshCookieOptions = (): express.CookieOptions => ({
  httpOnly: true,
  secure: SECURE_COOKIES,
  sameSite: COOKIE_SAMESITE,
  path: '/',
});

const stateCookieOptions = (): express.CookieOptions => ({
  httpOnly: true,
  secure: SECURE_COOKIES,
  sameSite: 'lax',
  path: '/',
});

/** The refresh token from the SSO's own cookie; any other cookie name is ignored. */
export function readRefreshToken(req: express.Request): string | undefined {
  const value: unknown = req.cookies?.[REFRESH_COOKIE];
  return typeof value === 'string' && value ? value : undefined;
}

/** Set the session cookies after a successful sign-in or refresh. */
export function setSessionCookies(res: express.Response, refreshToken: string): void {
  clearLegacyRefreshCookie(res);
  res.cookie(REFRESH_COOKIE, refreshToken, { ...refreshCookieOptions(), maxAge: SESSION_MAX_AGE_MS });
  res.cookie(HINT_COOKIE, '1', {
    httpOnly: false,
    secure: SECURE_COOKIES,
    sameSite: COOKIE_SAMESITE,
    path: '/',
    domain: parentDomain(),
    maxAge: SESSION_MAX_AGE_MS,
  });
}

/** Clear the session cookies, the old parent-domain refresh cookie included. */
export function clearSessionCookies(res: express.Response): void {
  clearLegacyRefreshCookie(res);
  res.clearCookie(REFRESH_COOKIE, refreshCookieOptions());
  res.clearCookie(HINT_COOKIE, { path: '/', domain: parentDomain(), secure: SECURE_COOKIES, sameSite: COOKIE_SAMESITE });
}

function clearLegacyRefreshCookie(res: express.Response): void {
  res.clearCookie(LEGACY_REFRESH_COOKIE, {
    path: '/',
    domain: parentDomain(),
    secure: SECURE_COOKIES,
    sameSite: COOKIE_SAMESITE,
    httpOnly: true,
  });
}

export type SignInState = { kind: 'flow' } | { kind: 'confirm'; nonce: string };

/** Record that the SSO started a sign-in flow in this browser (/login, a sign-in link). */
export function startSignInFlow(res: express.Response): void {
  res.cookie(STATE_COOKIE, `flow.${randomBytes(16).toString('base64url')}`, {
    ...stateCookieOptions(),
    maxAge: STATE_MAX_AGE_MS,
  });
}

/** Record a pending "Continue as ...?" question; returns the nonce its form must send back. */
export function askToConfirm(res: express.Response): string {
  const nonce = randomBytes(16).toString('base64url');
  res.cookie(STATE_COOKIE, `confirm.${nonce}`, { ...stateCookieOptions(), maxAge: STATE_MAX_AGE_MS });
  return nonce;
}

export function clearSignInState(res: express.Response): void {
  res.clearCookie(STATE_COOKIE, stateCookieOptions());
}

export function readSignInState(req: express.Request): SignInState | null {
  const value: unknown = req.cookies?.[STATE_COOKIE];
  if (typeof value !== 'string') return null;
  if (/^flow\.[A-Za-z0-9_-]{16,}$/.test(value)) return { kind: 'flow' };
  const confirm = /^confirm\.([A-Za-z0-9_-]{16,})$/.exec(value);
  return confirm ? { kind: 'confirm', nonce: confirm[1]! } : null;
}

/** True when the form's confirmation matches the pending question's nonce. */
export function confirmationMatches(state: SignInState | null, confirm: unknown): boolean {
  if (state?.kind !== 'confirm' || typeof confirm !== 'string') return false;
  const expected = Buffer.from(state.nonce);
  const given = Buffer.from(confirm);
  return expected.length === given.length && timingSafeEqual(expected, given);
}
