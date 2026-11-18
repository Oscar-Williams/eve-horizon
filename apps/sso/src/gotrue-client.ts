import { internalApiFetch } from '@eve/shared';
import { EVE_API_URL, EVE_INTERNAL_API_KEY, SUPABASE_ANON_KEY, SUPABASE_AUTH_URL } from './config.js';
import type { SsoLoginContext } from './types.js';

export async function internalApiPost<T>(path: string, body: Record<string, unknown>): Promise<T | null> {
  if (!EVE_INTERNAL_API_KEY) {
    console.error('[wrap] EVE_INTERNAL_API_KEY not configured — refusing to call internal API');
    return null;
  }
  try {
    const res = await internalApiFetch(path, {
      method: 'POST',
      body,
      baseUrl: EVE_API_URL,
      internalToken: EVE_INTERNAL_API_KEY,
    });
    if (!res.ok) {
      console.warn(`[wrap] ${path} returned ${res.status}`);
      return null;
    }
    return (await res.json()) as T;
  } catch (err) {
    console.error(`[wrap] ${path} fetch error:`, err);
    return null;
  }
}

export async function fetchAppContext(projectId: string | undefined): Promise<SsoLoginContext | null> {
  if (!projectId) return null;
  try {
    const res = await fetch(`${EVE_API_URL}/auth/app-context?project_id=${encodeURIComponent(projectId)}`);
    if (!res.ok) {
      console.error('[app-context] API returned', res.status, await res.text());
      return null;
    }
    return await res.json() as SsoLoginContext;
  } catch (err) {
    console.error('[app-context] Fetch error:', err);
    return null;
  }
}

/** Refresh a Supabase session using a refresh token. Returns { access_token, refresh_token }. */
export async function refreshSupabaseSession(
  refreshToken: string,
): Promise<{ access_token: string; refresh_token: string }> {
  const url = `${SUPABASE_AUTH_URL}/token?grant_type=refresh_token`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
    },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`GoTrue refresh failed (${res.status}): ${text}`);
  }

  return res.json() as Promise<{ access_token: string; refresh_token: string }>;
}

/** End one GoTrue session: `scope=local` signs out this session only, not the person's others. */
export async function endSupabaseSession(accessToken: string): Promise<void> {
  const res = await fetch(`${SUPABASE_AUTH_URL}/logout?scope=local`, {
    method: 'POST',
    headers: {
      apikey: SUPABASE_ANON_KEY,
      Authorization: `Bearer ${accessToken}`,
    },
  });
  if (!res.ok) {
    throw new Error(`GoTrue logout failed (${res.status})`);
  }
}

export type SessionOriginDecision = { profile: 'legacy' | 'audit' | 'strict'; allowed: boolean };

/**
 * Ask the Eve API whether this Origin may use /session or /logout, and under
 * which instance profile. Null when the API cannot answer.
 */
export async function checkSessionOrigin(input: {
  origin: string | null;
  project_id: string | null;
  purpose: 'session' | 'logout';
}): Promise<SessionOriginDecision | null> {
  try {
    const res = await fetch(`${EVE_API_URL}/auth/sso/check-origin`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(input),
    });
    if (!res.ok) {
      console.error('[session] origin check returned', res.status);
      return null;
    }
    const body = (await res.json()) as Partial<SessionOriginDecision>;
    if (!body || typeof body.allowed !== 'boolean' || !['legacy', 'audit', 'strict'].includes(String(body.profile))) {
      return null;
    }
    return body as SessionOriginDecision;
  } catch (err) {
    console.error('[session] origin check failed:', err instanceof Error ? err.message : String(err));
    return null;
  }
}

/** The API refused a token for this caller (403): the session itself stays good. */
export class SessionRefusedError extends Error {}

/** Ask the Eve API for the token /session returns to this Origin and project. */
export async function issueSessionToken(
  supabaseAccessToken: string,
  input: { origin: string | null; project_id: string | null },
): Promise<{ access_token: string; expires_at: number | string; user_id: string }> {
  const res = await fetch(`${EVE_API_URL}/auth/sso/session`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${supabaseAccessToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(input),
  });
  if (res.status === 403) {
    throw new SessionRefusedError('Not allowed for this app');
  }
  if (!res.ok) {
    throw new Error(`Eve session token failed (${res.status})`);
  }
  return res.json() as Promise<{ access_token: string; expires_at: number | string; user_id: string }>;
}

/** Exchange a Supabase access token for an Eve RS256 token via the Eve API. */
export async function exchangeForEveToken(
  supabaseAccessToken: string,
): Promise<{
  access_token: string;
  expires_at: string;
  user_id: string;
  invite_redirect_to?: string;
  invite_org_id?: string;
  invite_app_context?: { project_id?: string; org_id?: string } & Record<string, unknown>;
}> {
  const url = `${EVE_API_URL}/auth/exchange`;
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${supabaseAccessToken}`,
      'Content-Type': 'application/json',
    },
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Eve exchange failed (${res.status}): ${text}`);
  }

  return res.json() as Promise<{
    access_token: string;
    expires_at: string;
    user_id: string;
    invite_redirect_to?: string;
    invite_org_id?: string;
    invite_app_context?: { project_id?: string; org_id?: string } & Record<string, unknown>;
  }>;
}

/** Decode a JWT payload without verification (for extracting email/user info from Supabase token). */
export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], 'base64url').toString('utf-8');
    return JSON.parse(payload);
  } catch {
    return null;
  }
}
