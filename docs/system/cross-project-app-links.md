# Cross-Project App Links

> Status: Current
> Last Updated: 2026-05-15

App links let one project consume another project's API, CLI, and app events without shared long-lived secrets.

## Manifest Shape

Producer projects declare exports at `x-eve.app_links.exports`.

```yaml
x-eve:
  app_links:
    exports:
      apis:
        observation:
          service: api
          cli: obs
          scopes: [observations:read, deployments:read]
          consumers:
            - project: consumer
              scopes: [observations:read]
              envs: [staging]
      events:
        observation-feed:
          types: [app.observation.created]
          consumers:
            - project: consumer
```

Consumer projects declare subscriptions at `x-eve.app_links.consumes`.

```yaml
x-eve:
  app_links:
    consumes:
      observation:
        project: producer
        api: observation
        environment: same
        scopes: [observations:read]
        events:
          feed: observation-feed
          types: [app.observation.created]
        inject_into:
          services: [api]
          jobs: true
```

## Runtime Contract

Injected service and job surfaces receive:

- `EVE_APP_LINK_<ALIAS>_API_URL`
- `EVE_APP_LINK_<ALIAS>_TOKEN`
- `EVE_APP_LINK_<ALIAS>_SCOPES`
- `EVE_APP_LINK_<ALIAS>_PROJECT`
- `EVE_APP_LINK_<ALIAS>_ENV`
- `EVE_APP_LINK_<ALIAS>_CLI` when the producer exported an image-mode CLI

Tokens are Eve-signed RS256 JWTs with `type: "app_link"` and `aud: "project:<producer_project_id>"`. Verification re-reads the active grant/subscription so producer revocation is effective without waiting for token expiry.

### Job tokens: lifetime and refresh

A job's link tokens (principal `job:<id>`) last an hour and carry the job's
`attempt_id`. Eve refuses them as soon as that attempt is no longer the job's
running attempt, or the job is cancelled; a token minted without an attempt is
refused once the job is done. This holds wherever Eve verifies the token
(`/auth/me`, `/auth/token/verify`, the auth SDK's default `remote` strategy).
A producer that verifies locally against JWKS (`strategy: 'local'`) sees only
`exp`, so it should verify job principals remotely. The same holds for a
deployed service's link token (principal `service:<name>`): `eve env
rotate-service-tokens` and the environment's deletion revoke it only where Eve
verifies it (see [auth](auth.md), service tokens).

A job that runs longer than an hour refreshes its own tokens with its job token:

```bash
export EVE_APP_LINK_SHOP_TOKEN=$(eve job app-link-token shop)   # one link
eval "$(eve job app-link-token --env)"                           # every link
```

App links are project-scoped: a job's links come from
`hints.resolved_app_links`, which any `jobs:write` holder in the consumer
project can edit, so the refresh (like the first mint) covers any of the
project's subscriptions a job names there. A secrets allowlist does not limit
app links.

`POST /jobs/{job_id}/app-link-tokens` (body `{ "alias"?: string }`) answers
`{ data: [{ alias, name, env_var, access_token, expires_at }] }`. Only the
job's own job token may call it, and only while the job runs. The harness's
original `EVE_APP_LINK_<ALIAS>_TOKEN` cannot be changed from outside the
process, so a refreshed token is used from the shell that fetched it. The
app-API instructions in a job's description tell the agent to refresh on a 401.

## Events

Producer events fan out through `app_link_event_deliveries`. Consumer events are inserted with `source: app_link`, the original event type, and a dedupe key of `app_link:<subscription_id>:<source_event_id>`.

Consumers can trigger workflows with:

```yaml
trigger:
  app_link:
    alias: observation
    type: app.observation.created
```

## Diagnostics

Use:

```bash
eve app-links list --project <project>
eve app-links plan --project <consumer> --file .eve/manifest.yaml
eve app-links explain --consumer <consumer> --alias observation
```
