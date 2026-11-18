import { escapeHtml, pageChrome } from './chrome.js';

/**
 * "Continue as x@y?" — shown when tokens reach /callback in a browser that
 * did not start the sign-in (an admin invite, or a link opened elsewhere).
 * Continuing posts the same tokens back with the confirmation nonce.
 */
export function continueAsHtml(opts: { email: string | null; fields: Record<string, string> }): string {
  const who = opts.email ? escapeHtml(opts.email) : 'this account';
  const hidden = Object.entries(opts.fields)
    .filter(([, value]) => value !== '')
    .map(([name, value]) => `        <input type="hidden" name="${escapeHtml(name)}" value="${escapeHtml(value)}">`)
    .join('\n');

  const head = `  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>Eve - Continue signing in</title>`;

  const css = `    *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a0a; color: #e5e5e5;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh; padding: 1rem;
    }
    .card { width: 100%; max-width: 440px; background: #141414; border: 1px solid #262626; border-radius: 12px; padding: 2rem; text-align: center; }
    .card h2 { font-size: 1.125rem; font-weight: 600; color: #fff; margin-bottom: 0.5rem; }
    .card p { color: #a3a3a3; font-size: 0.9375rem; line-height: 1.5; margin-bottom: 1.5rem; }
    .card p strong { color: #e5e5e5; }
    .btn { width: 100%; padding: 0.75rem 1rem; border: none; border-radius: 8px; font-size: 0.9375rem; font-weight: 500; cursor: pointer; background: #fff; color: #0a0a0a; }
    .btn:hover { opacity: 0.88; }
    .other { display: block; margin-top: 1rem; color: #a3a3a3; font-size: 0.875rem; }`;

  const body = `  <div class="card">
    <h2>Continue as ${who}?</h2>
    <p>This sign-in was not started in this browser. Continue only if <strong>${who}</strong> is you.</p>
    <form method="POST" action="/callback" autocomplete="off">
${hidden}
      <button type="submit" class="btn">Continue as ${who}</button>
    </form>
    <a class="other" href="/login">Not you? Sign in with another account</a>
  </div>`;

  return pageChrome(body, { head, css });
}
