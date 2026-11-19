import express from 'express';
import type { Express } from 'express';
import { SECURE_COOKIES } from '../config.js';
import {
  askToConfirm,
  clearSignInState,
  confirmationMatches,
  readSignInState,
  setSessionCookies,
} from '../cookies.js';
import { decodeJwtPayload, exchangeForEveToken, fetchAppContext } from '../gotrue-client.js';
import { isAllowedRedirect } from '../security.js';
import { cspNonce } from '../csp.js';
import { appendQueryParam, buildQuery, ssoOrigin } from '../urls.js';
import { callbackExtractorHtml } from '../views/callback-extractor.js';
import { continueAsHtml } from '../views/continue-as.js';

const field = (value: unknown): string => (typeof value === 'string' ? value : '');

export function registerCallbackRoutes(app: Express): void {
  app.get('/callback', (req, res) => {
    const projectId = field(req.query.project_id);
    const redirectTo = field(req.query.redirect_to);

    // Tokens are taken only in a POST from the SSO's own pages: a link must
    // not be able to sign a browser in, and tokens must stay out of URLs.
    if (req.query.access_token !== undefined || req.query.refresh_token !== undefined) {
      res.redirect(302, `/login${buildQuery({
        error: 'Sign-in failed. Please try again.',
        redirect_to: redirectTo,
        project_id: projectId,
      })}`);
      return;
    }

    // GoTrue surfaces redemption failures via ?error= / ?error_code= query
    // params (or the hash fragment — handled in callbackExtractorHtml). Surface
    // those to /login instead of letting the user spin on "Authenticating...".
    const errorCode = (req.query.error_code as string) || (req.query.error as string);
    if (errorCode) {
      const friendly = errorCode === 'otp_expired'
        ? 'This sign-in link has already been used or has expired. Please request a new sign-in link or ask for a new invite.'
        : 'Authentication failed. Please try again.';
      const loginUrl = `/login${buildQuery({
        error: friendly,
        error_code: errorCode,
        redirect_to: redirectTo,
        project_id: projectId,
      })}`;
      res.redirect(302, loginUrl);
      return;
    }

    // GoTrue puts the tokens in the URL fragment; this page posts them back.
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(callbackExtractorHtml(cspNonce(res)));
  });

  app.post('/callback', express.urlencoded({ extended: false }), async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Referrer-Policy', 'no-referrer');

    if (req.headers.origin !== ssoOrigin(req)) {
      res.status(403).type('text').send('Forbidden');
      return;
    }

    const accessToken = field(req.body?.access_token);
    const refreshToken = field(req.body?.refresh_token);
    const authType = field(req.body?.type);
    let projectId = field(req.body?.project_id);
    let redirectTo = field(req.body?.redirect_to);

    if (!accessToken || !refreshToken) {
      res.redirect(302, `/login${buildQuery({
        error: 'Sign-in failed. Please try again.',
        redirect_to: redirectTo,
        project_id: projectId,
      })}`);
      return;
    }

    // Set a session only for a sign-in this browser started, or one the
    // person has just confirmed. Otherwise ask, so a planted link cannot sign
    // a browser in as someone else.
    const state = readSignInState(req);
    if (state?.kind !== 'flow' && !confirmationMatches(state, req.body?.confirm)) {
      const email = decodeJwtPayload(accessToken)?.email;
      const confirm = askToConfirm(res);
      res.status(200).type('html').send(continueAsHtml({
        email: typeof email === 'string' && email ? email : null,
        fields: {
          access_token: accessToken,
          refresh_token: refreshToken,
          type: authType,
          project_id: projectId,
          redirect_to: redirectTo,
          confirm,
        },
      }));
      return;
    }
    clearSignInState(res);

    try {
      // Exchange the Supabase access token for an Eve RS256 token
      const exchangeResult = await exchangeForEveToken(accessToken);

      // Set root-domain cookies with the refresh token
      setSessionCookies(res, refreshToken);

      // If an invite was applied during exchange and it has a redirect_to,
      // use that as the redirect target (GoTrue strips nested redirect params).
      if (!redirectTo && exchangeResult.invite_redirect_to) {
        redirectTo = exchangeResult.invite_redirect_to;
      }

      // Recover project context from invite_app_context when GoTrue dropped it
      // from the callback query (common for the invite flow).
      if (!projectId && exchangeResult.invite_app_context?.project_id) {
        projectId = exchangeResult.invite_app_context.project_id;
      }

      // Fetch app context once so the redirect validator can consult the
      // project-declared allowlist.
      const context = await fetchAppContext(projectId);
      const allowedOrigins = context?.auth?.allowed_redirect_origins ?? [];

      // Validate redirect target against cluster + project-declared origins.
      if (!redirectTo || !isAllowedRedirect(redirectTo, { allowedOrigins })) {
        if (redirectTo) {
          console.warn(
            `[callback] Rejected redirect_to=${redirectTo} (project_id=${projectId || 'none'}, allowed=${allowedOrigins.join(',') || 'none'})`,
          );
        }
        // Default: redirect to the SSO broker root, using the request host
        const proto = SECURE_COOKIES ? 'https' : 'http';
        redirectTo = `${proto}://${req.hostname}/`;
      }

      if (exchangeResult.invite_org_id && isAllowedRedirect(redirectTo, { allowedOrigins })) {
        redirectTo = appendQueryParam(redirectTo, 'eve_org_id', exchangeResult.invite_org_id);
      }

      // For invite flows, redirect to the password-set page first.
      // The user's session is established (cookies set), but they need to
      // choose a password before being sent to the target app.
      if (authType === 'invite') {
        if (context?.auth?.invite_requires_password === false) {
          res.redirect(302, redirectTo);
          return;
        }
        const setPasswordUrl = `/set-password${buildQuery({ redirect_to: redirectTo, project_id: projectId })}`;
        res.redirect(302, setPasswordUrl);
        return;
      }

      res.redirect(302, redirectTo);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Authentication failed';
      console.error('[callback] Exchange error:', message);
      const loginUrl = `/login${buildQuery({
        error: 'Authentication failed. Please try again.',
        redirect_to: redirectTo,
        project_id: projectId,
      })}`;
      res.redirect(302, loginUrl);
    }
  });
}
