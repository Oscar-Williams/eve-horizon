import {
  COOKIE_SAMESITE,
  EVE_API_URL,
  EVE_DEFAULT_DOMAIN,
  PORT,
  SECURE_COOKIES,
  SIGNUP_ALLOWED_DOMAINS,
  SUPABASE_AUTH_URL,
} from './config.js';
import { createApp } from './app.js';

const app = createApp();

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[eve-sso] Listening on port ${PORT}`);
  console.log(`[eve-sso] Domain: ${EVE_DEFAULT_DOMAIN}`);
  console.log(`[eve-sso] GoTrue (internal): ${SUPABASE_AUTH_URL}`);
  console.log(`[eve-sso] GoTrue (proxied via /auth/*)`);

  console.log(`[eve-sso] Eve API: ${EVE_API_URL}`);
  console.log(`[eve-sso] Secure cookies: ${SECURE_COOKIES} (SameSite=${COOKIE_SAMESITE})`);
  console.log(`[eve-sso] Signup domain restriction: ${SIGNUP_ALLOWED_DOMAINS.length > 0 ? SIGNUP_ALLOWED_DOMAINS.join(', ') : 'none (all domains allowed)'}`);
});
