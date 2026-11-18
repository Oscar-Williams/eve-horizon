import { POST_TO_CALLBACK_SCRIPT, pageChrome } from './chrome.js';

export function callbackExtractorHtml(): string {
  const head = `  <title>Eve - Authenticating...</title>`;

  const css = `    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      background: #0a0a0a;
      color: #e5e5e5;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .msg { text-align: center; }
    .msg p { color: #737373; font-size: 0.875rem; margin-top: 0.5rem; }`;

  const body = `  <div class="msg">
    <h2>Authenticating...</h2>
    <p>Please wait while we complete your sign-in.</p>
  </div>
  <script>
${POST_TO_CALLBACK_SCRIPT}

    // GoTrue redirects here with the tokens (or an error) in the URL fragment.
    (function readFragment() {
      const hash = window.location.hash;
      if (!hash || hash.length < 2) return;
      const hashParams = new URLSearchParams(hash.substring(1));
      const queryParams = new URLSearchParams(window.location.search);

      // A redemption failure (e.g. #error=access_denied&error_code=otp_expired)
      // goes to /callback without tokens, which sends the person to /login
      // with a message instead of spinning here.
      const errorCode = hashParams.get('error_code') || hashParams.get('error');
      if (errorCode) {
        const errorParams = new URLSearchParams();
        errorParams.set('error_code', errorCode);
        const description = hashParams.get('error_description');
        if (description) errorParams.set('error_description', description);
        for (const key of ['redirect_to', 'project_id']) {
          const value = queryParams.get(key);
          if (value) errorParams.set(key, value);
        }
        window.location.replace('/callback?' + errorParams.toString());
        return;
      }

      const accessToken = hashParams.get('access_token');
      const refreshToken = hashParams.get('refresh_token');
      if (!accessToken || !refreshToken) return;
      history.replaceState(null, '', window.location.pathname + window.location.search);
      postToCallback({
        access_token: accessToken,
        refresh_token: refreshToken,
        type: hashParams.get('type') || '',
        redirect_to: queryParams.get('redirect_to') || '',
        project_id: queryParams.get('project_id') || '',
      });
    })();
  </script>`;

  return pageChrome(body, { head, css });
}
