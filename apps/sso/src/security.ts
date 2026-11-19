import express from 'express';
import { createHmac, timingSafeEqual } from 'crypto';
import { EVE_DEFAULT_DOMAIN, EVE_INTERNAL_API_KEY, EVE_INTERNAL_SSO_KEY, SIGNUP_ALLOWED_DOMAINS } from './config.js';
import { checkSessionOrigin, fetchAppContext } from './gotrue-client.js';

// Wrap tokens have the typeid('mlw') shape: lowercase prefix + 26-char base32.
// Validating against this regex before hitting the API gives scanners crafting
// malformed paths a quick 404 and avoids logging arbitrary user input.
const WRAP_TOKEN_REGEX = /^mlw_[0-9a-z]{26}$/;

const LOCAL_HTTP_HOSTNAMES = new Set(['localhost', '127.0.0.1', '0.0.0.0', '::1']);

export function isLocalHttpOrigin(parsed: URL): boolean {
  if (parsed.protocol !== 'http:') return false;
  const host = parsed.hostname.toLowerCase();
  if (LOCAL_HTTP_HOSTNAMES.has(host)) return true;
  if (host === 'lvh.me' || host.endsWith('.lvh.me')) return true;
  return false;
}

export function isClusterDomainHost(host: string): boolean {
  return host === EVE_DEFAULT_DOMAIN || host.endsWith(`.${EVE_DEFAULT_DOMAIN}`);
}

export function normalizeOrigin(value: string): string | null {
  try {
    return new URL(value).origin;
  } catch {
    return null;
  }
}

/**
 * Validate a post-auth `redirect_to` URL (http or https only). Accepts:
 *   - Any URL whose hostname is the cluster domain or a subdomain of it.
 *   - Any URL whose origin matches a project-declared allowed origin.
 * Project-declared origins must be HTTPS (or local-only HTTP for dev).
 */
export function isAllowedRedirect(
  url: string,
  context: { allowedOrigins?: string[] } = {},
): boolean {
  try {
    const parsed = new URL(url);
    // Only web addresses: never javascript:, data: or other schemes, even on
    // a cluster host.
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
      return false;
    }
    if (isClusterDomainHost(parsed.hostname)) {
      return true;
    }
    if (parsed.protocol !== 'https:' && !isLocalHttpOrigin(parsed)) {
      return false;
    }
    const allowed = (context.allowedOrigins ?? [])
      .map(normalizeOrigin)
      .filter((origin): origin is string => Boolean(origin));
    return allowed.includes(parsed.origin);
  } catch {
    return false;
  }
}

/** Validate a CORS request `Origin` against cluster + project-declared origins. */
export function isAllowedOrigin(
  origin: string,
  context: { allowedOrigins?: string[] } = {},
): boolean {
  try {
    const parsed = new URL(origin);
    if (isClusterDomainHost(parsed.hostname)) {
      return true;
    }
    if (parsed.protocol !== 'https:' && !isLocalHttpOrigin(parsed)) {
      return false;
    }
    const allowed = (context.allowedOrigins ?? [])
      .map(normalizeOrigin)
      .filter((o): o is string => Boolean(o));
    return allowed.includes(parsed.origin);
  } catch {
    return false;
  }
}

/** Check whether an email is allowed for self-signup. Returns true when unrestricted. */
export function isSignupEmailAllowed(email: string): boolean {
  if (SIGNUP_ALLOWED_DOMAINS.length === 0) return true;
  const domain = email.split('@')[1]?.toLowerCase();
  return !!domain && SIGNUP_ALLOWED_DOMAINS.includes(domain);
}

/**
 * The CSRF value for a sign-in link form: HMAC-SHA256, keyed with the SSO's
 * own key (the legacy internal key until that is set), of the wrap token and
 * this browser's flow nonce (from its host-only state cookie). A value read
 * in one browser does not work in another; the wrap token itself remains the
 * bearer credential.
 */
export function signWrapCsrf(wrapToken: string, flowNonce: string): string {
  const key = EVE_INTERNAL_SSO_KEY || EVE_INTERNAL_API_KEY;
  if (!key) {
    throw new Error('EVE_INTERNAL_SSO_KEY or EVE_INTERNAL_API_KEY is required to sign sign-in link forms');
  }
  return wrapCsrf(key, wrapToken, flowNonce);
}

function wrapCsrf(key: string, wrapToken: string, flowNonce: string): string {
  return createHmac('sha256', key).update(`${wrapToken}\n${flowNonce}`).digest('hex');
}

/**
 * Check a sign-in link form's CSRF value. A form rendered under the legacy
 * key still submits while that key is set, so switching to the SSO key does
 * not break a sign-in in progress.
 */
export function verifyWrapCsrf(wrapToken: string, flowNonce: string | undefined, nonce: string): boolean {
  if (!flowNonce || !nonce || nonce.length !== 64) return false;
  const presented = Buffer.from(nonce, 'hex');
  if (presented.length !== 32) return false;
  return [EVE_INTERNAL_SSO_KEY, EVE_INTERNAL_API_KEY]
    .filter(Boolean)
    .some((key) => timingSafeEqual(Buffer.from(wrapCsrf(key, wrapToken, flowNonce), 'hex'), presented));
}

export function isValidWrapToken(token: string): boolean {
  return WRAP_TOKEN_REGEX.test(token);
}

export async function applyCorsHeaders(req: express.Request, res: express.Response): Promise<boolean> {
  const origin = req.headers.origin;
  // Same-origin requests may omit the Origin header. In that case, CORS is not
  // relevant and we should allow the request to proceed.
  if (!origin) return true;

  // Cluster-domain origins are always allowed (no project context needed).
  let parsed: URL | null = null;
  try {
    parsed = new URL(origin);
  } catch {
    res.status(403).json({ error: 'Origin not allowed' });
    return false;
  }

  if (isClusterDomainHost(parsed.hostname)) {
    setCorsHeaders(res, origin);
    return true;
  }

  // Non-cluster origins must declare their project context so the SSO can
  // consult the project-scoped allowlist. Without a project, we cannot trust
  // any external origin.
  const projectId = (req.query.project_id as string) || '';
  if (!projectId) {
    res.status(403).json({ error: 'Origin not allowed (project_id required for cross-domain requests)' });
    return false;
  }

  const context = await fetchAppContext(projectId);
  const allowedOrigins = context?.auth?.allowed_redirect_origins ?? [];
  if (!isAllowedOrigin(origin, { allowedOrigins })) {
    console.warn(
      `[cors] Rejected origin=${origin} (project_id=${projectId}, allowed=${allowedOrigins.join(',') || 'none'})`,
    );
    res.status(403).json({ error: 'Origin not allowed' });
    return false;
  }

  setCorsHeaders(res, origin);
  return true;
}

function setCorsHeaders(res: express.Response, origin: string): void {
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');
}

/**
 * Admit a /session or /logout request by its Origin. The Eve API decides
 * under the instance security profile: under `strict` only the origins it
 * allows are served (the dashboard, or a host of the named app); under
 * `legacy` and `audit` the older rules above apply, and the API records what
 * `strict` would refuse. Answers 403 or 503 itself and returns false when the
 * request may not go on.
 */
export async function admitSessionOrigin(
  req: express.Request,
  res: express.Response,
  purpose: 'session' | 'logout',
): Promise<boolean> {
  const rawOrigin = req.headers.origin;
  const origin = typeof rawOrigin === 'string' && rawOrigin ? rawOrigin : null;
  const projectId = typeof req.query.project_id === 'string' && req.query.project_id ? req.query.project_id : null;

  const decision = await checkSessionOrigin({ origin, project_id: projectId, purpose });
  if (!decision) {
    res.status(503).json({ error: 'Sign-in service unavailable' });
    return false;
  }
  if (decision.profile !== 'strict') {
    return applyCorsHeaders(req, res);
  }
  if (!decision.allowed || !origin) {
    res.status(403).json({ error: 'Origin not allowed' });
    return false;
  }
  setCorsHeaders(res, origin);
  return true;
}
