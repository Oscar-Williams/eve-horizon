import type { Express } from 'express';
import { EVE_API_URL, SIGNUP_ALLOWED_DOMAINS, SUPABASE_ANON_KEY, SUPABASE_AUTH_URL } from '../config.js';
import { readRefreshToken, startSignInFlow } from '../cookies.js';
import { fetchAppContext } from '../gotrue-client.js';
import { isAllowedRedirect, isSignupEmailAllowed } from '../security.js';
import { cspNonce } from '../csp.js';
import { buildQuery, ssoOrigin } from '../urls.js';
import { loginPageHtml } from '../views/login.js';

export function registerLoginRoutes(app: Express): void {
  // -------------------------------------------------------------------------
  // GET /login
  // -------------------------------------------------------------------------

  app.get('/login', async (req, res) => {
    const redirectTo = (req.query.redirect_to as string) || '';
    const projectId = (req.query.project_id as string) || '';
    const mode = (req.query.mode as string) || 'signin';
    const error = (req.query.error as string) || undefined;
    const context = await fetchAppContext(projectId);

    // If the user already has a session and the request carries a validated
    // redirect target, bypass the login form entirely. The form is a dead end
    // for a signed-in user otherwise.
    if (readRefreshToken(req) && redirectTo) {
      const allowedOrigins = context?.auth?.allowed_redirect_origins ?? [];
      if (isAllowedRedirect(redirectTo, { allowedOrigins })) {
        res.redirect(302, redirectTo);
        return;
      }
    }

    // A sign-in started here comes back to /callback with this flow's nonce:
    // the password sign-in posts it from this page, and a magic link carries
    // it through GoTrue's redirect_to.
    const flow = startSignInFlow(req, res);
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(loginPageHtml(redirectTo, mode, error, context, { scriptNonce: cspNonce(res), flow }));
  });

  // -------------------------------------------------------------------------
  // POST /auth/token — proxy sign-in to GoTrue (same-origin, no CORS)
  // -------------------------------------------------------------------------

  app.post('/auth/token', async (req, res) => {
    try {
      const gotrueRes = await fetch(`${SUPABASE_AUTH_URL}/token?grant_type=password`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
        },
        body: JSON.stringify(req.body),
      });
      const data = await gotrueRes.text();
      res.status(gotrueRes.status).type('json').send(data);
    } catch (err) {
      console.error('[auth/token] Proxy error:', err);
      res.status(502).json({ error: 'Authentication service unavailable' });
    }
  });

  // -------------------------------------------------------------------------
  // POST /auth/signup — proxy sign-up to GoTrue (same-origin, no CORS)
  // -------------------------------------------------------------------------

  app.post('/auth/signup', async (req, res) => {
    const email = req.body?.email;
    if (email && !isSignupEmailAllowed(email)) {
      const hint = SIGNUP_ALLOWED_DOMAINS.join(', ');
      res.status(422).json({ error: 'email_domain_not_allowed', msg: `Signup is restricted to: ${hint}` });
      return;
    }
    try {
      const gotrueRes = await fetch(`${SUPABASE_AUTH_URL}/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
        },
        body: JSON.stringify(req.body),
      });
      const data = await gotrueRes.text();
      res.status(gotrueRes.status).type('json').send(data);
    } catch (err) {
      console.error('[auth/signup] Proxy error:', err);
      res.status(502).json({ error: 'Authentication service unavailable' });
    }
  });

  // -------------------------------------------------------------------------
  // POST /auth/magiclink — proxy magic link to GoTrue (same-origin, no CORS)
  // -------------------------------------------------------------------------

  app.post('/auth/magiclink', async (req, res) => {
    const email = req.body?.email;
    const projectId = req.body?.project_id;
    const redirectTo = req.body?.redirect_to;
    if (projectId) {
      try {
        const apiRes = await fetch(`${EVE_API_URL}/auth/magic-link`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            project_id: projectId,
            ...(typeof redirectTo === 'string' && redirectTo ? { redirect_to: redirectTo } : {}),
          }),
        });
        const data = await apiRes.text();
        res.status(apiRes.status).type('json').send(data);
      } catch (err) {
        console.error('[auth/magiclink] Eve API proxy error:', err);
        res.status(502).json({ error: 'Authentication service unavailable' });
      }
      return;
    }

    if (email && !isSignupEmailAllowed(email)) {
      const hint = SIGNUP_ALLOWED_DOMAINS.join(', ');
      res.status(422).json({ error: 'email_domain_not_allowed', msg: `Signup is restricted to: ${hint}` });
      return;
    }
    // GoTrue sends the link back to the SSO, which then forwards to the
    // requested address. GoTrue only accepts its own site (the SSO) as a
    // return address, so the final target travels inside it, with this
    // browser's flow nonce.
    const flow = startSignInFlow(req, res);
    const returnTo = magicLinkReturnAddress(ssoOrigin(req), typeof redirectTo === 'string' ? redirectTo : '', flow);
    try {
      const gotrueRes = await fetch(`${SUPABASE_AUTH_URL}/magiclink${buildQuery({ redirect_to: returnTo })}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          apikey: SUPABASE_ANON_KEY,
          Authorization: `Bearer ${SUPABASE_ANON_KEY}`,
        },
        body: JSON.stringify({ email }),
      });
      if (!gotrueRes.ok) {
        console.warn(`[auth/magiclink] GoTrue answered ${gotrueRes.status}`);
      }
    } catch (err) {
      console.error('[auth/magiclink] Proxy error:', err instanceof Error ? err.message : String(err));
      res.status(502).json({ error: 'Authentication service unavailable' });
      return;
    }
    // One reply whatever GoTrue said: a different one would tell anyone
    // whether an account exists for the address.
    res.json({});
  });
}

/**
 * Where GoTrue sends a dashboard sign-in link: the SSO's landing page, with
 * this browser's flow nonce and, when it is one the SSO may send people to,
 * the requested address as its `redirect_to`.
 */
export function magicLinkReturnAddress(sso: string, redirectTo: string, flow?: string): string {
  const onward = redirectTo && isAllowedRedirect(redirectTo) ? redirectTo : undefined;
  return `${sso}/${buildQuery({ flow, redirect_to: onward })}`;
}
