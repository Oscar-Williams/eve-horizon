import { randomBytes } from 'crypto';
import type express from 'express';

/**
 * Content-Security-Policy for every SSO response: inline scripts run only
 * with this response's nonce, so markup that slips past escaping cannot run
 * script. Styles, images and form targets are left open (pages carry inline
 * styles and app logos, and sign-in forms redirect to GoTrue and apps).
 */
export function contentSecurityPolicy(_req: express.Request, res: express.Response, next: express.NextFunction): void {
  const nonce = randomBytes(16).toString('base64');
  res.locals.cspNonce = nonce;
  res.setHeader('Content-Security-Policy', `script-src 'nonce-${nonce}'; object-src 'none'; base-uri 'none'`);
  next();
}

/** The CSP nonce for this response's inline scripts. */
export function cspNonce(res: express.Response): string | undefined {
  const nonce: unknown = res.locals.cspNonce;
  return typeof nonce === 'string' ? nonce : undefined;
}
