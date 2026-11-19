# @eve-horizon/auth

Backend auth SDK for Eve-compatible apps. Verify Eve tokens and check org membership with Express middleware.

## Install

```bash
npm install @eve-horizon/auth
```

## Quick Start

```typescript
import { eveUserAuth, eveAuthGuard, eveAuthConfig } from '@eve-horizon/auth';

// Parse tokens and check org membership (non-blocking)
app.use(eveUserAuth());

// Serve auth discovery config
app.get('/auth/config', eveAuthConfig());

// Protected route
app.get('/auth/me', eveAuthGuard(), (req, res) => res.json(req.eveUser));

// Protect all API routes
app.use('/api', eveAuthGuard());
```

For apps that use Eve app-org access policies, switch to `eveAppUserAuth()`:

```typescript
import { eveAppUserAuth, eveAuthGuard, eveAuthConfig } from '@eve-horizon/auth';

app.use(eveAppUserAuth());
app.get('/auth/config', eveAuthConfig());
app.use('/api', eveAuthGuard());
```

## Environment Variables

Set automatically when deployed to Eve:

| Variable | Purpose |
|----------|---------|
| `EVE_API_URL` | JWKS fetch + remote token verification |
| `EVE_ORG_ID` | Org membership check |
| `EVE_SSO_URL` | Auth config discovery |
| `EVE_PROJECT_ID` | App-scoped org access lookup; the app's own token audience |
| `EVE_ENV_NAME` | The app's own token audience |

## App audience tokens

When the Eve instance runs the `strict` security profile, the SSO gives an
app a one-hour token whose `aud` names the app
(`eve-app:<EVE_PROJECT_ID>:<EVE_ENV_NAME>`, or `eve-app:<EVE_PROJECT_ID>`)
and which carries no `orgs` claim. The middleware accepts such a token only
for the app's own audience, reads the person's orgs from Eve
`/auth/app-access`, and sends `X-Eve-Audience` whenever it asks Eve about the
token. To call Eve yourself, add `eveAudienceHeaders(token)` to the request
headers.

## Docs

Full reference: [Eve Auth SDK Documentation](https://github.com/eve-horizon/eve-horizon/blob/main/docs/system/eve-auth-sdk.md)
