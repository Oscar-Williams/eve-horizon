import type { Express } from 'express';
import { clearSessionCookies, readRefreshToken, setSessionCookies } from '../cookies.js';
import {
  SessionRefusedError,
  decodeJwtPayload,
  endSupabaseSession,
  issueSessionToken,
  refreshSupabaseSession,
} from '../gotrue-client.js';
import { admitSessionOrigin } from '../security.js';
import { ssoOrigin } from '../urls.js';

function requestOrigin(origin: string | string[] | undefined): string | null {
  return typeof origin === 'string' && origin ? origin : null;
}

export function registerSessionRoutes(app: Express): void {
  // -------------------------------------------------------------------------
  // OPTIONS + GET /session  (CORS-enabled with credentials)
  // -------------------------------------------------------------------------

  app.options('/session', async (req, res) => {
    if (await admitSessionOrigin(req, res, 'session')) {
      res.status(204).end();
    }
  });

  app.get('/session', async (req, res) => {
    if (!await admitSessionOrigin(req, res, 'session')) return;

    const refreshToken = readRefreshToken(req);
    if (!refreshToken) {
      res.status(401).json({ error: 'No session' });
      return;
    }

    try {
      // Refresh the Supabase session; GoTrue rotates the refresh token.
      const supabase = await refreshSupabaseSession(refreshToken);
      setSessionCookies(res, supabase.refresh_token);

      // The API decides what token this origin gets (see /auth/sso/session).
      const eve = await issueSessionToken(supabase.access_token, {
        origin: requestOrigin(req.headers.origin),
        project_id: typeof req.query.project_id === 'string' && req.query.project_id ? req.query.project_id : null,
      });

      const claims = decodeJwtPayload(supabase.access_token);
      const email = (claims?.email as string) || '';

      res.json({
        access_token: eve.access_token,
        expires_at: eve.expires_at,
        user: {
          id: eve.user_id,
          email,
        },
      });
    } catch (err) {
      if (err instanceof SessionRefusedError) {
        // Refused for this app or visitor; the session itself stays.
        res.status(403).json({ error: 'Not allowed for this app' });
        return;
      }
      const message = err instanceof Error ? err.message : 'Session refresh failed';
      console.error('[session] Error:', message);

      // If refresh fails, the session is invalid -- clear cookies
      clearSessionCookies(res);
      res.status(401).json({ error: 'Session expired' });
    }
  });

  // -------------------------------------------------------------------------
  // OPTIONS + POST /logout  (CORS-enabled)
  // -------------------------------------------------------------------------

  app.options('/logout', async (req, res) => {
    if (await admitSessionOrigin(req, res, 'logout')) {
      res.status(204).end();
    }
  });

  app.post('/logout', async (req, res) => {
    // A sign-out comes from a browser page: the SSO's own, or an origin the
    // instance profile admits (rule sso.session_origin). No Origin, no
    // sign-out.
    const origin = requestOrigin(req.headers.origin);
    if (!origin) {
      res.status(403).json({ error: 'Origin required' });
      return;
    }
    if (origin !== ssoOrigin(req) && !await admitSessionOrigin(req, res, 'logout')) return;

    // End this GoTrue session, not just the cookies. GoTrue's logout needs an
    // access token, so refresh once first.
    const refreshToken = readRefreshToken(req);
    if (refreshToken) {
      try {
        const supabase = await refreshSupabaseSession(refreshToken);
        await endSupabaseSession(supabase.access_token);
      } catch (err) {
        console.warn('[logout] Could not end the GoTrue session:', err instanceof Error ? err.message : String(err));
      }
    }

    clearSessionCookies(res);
    res.json({ ok: true });
  });
}
