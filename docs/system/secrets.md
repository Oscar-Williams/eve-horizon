# Secrets

> Status: Current
> Last Updated: 2026-11-19

## Overview

Eve Horizon supports multi-level secrets scoped to system/org/user/project plus host-provided env for local development.
Secrets are encrypted at rest in the database and never returned in plaintext by the API.

## Host Env (local)

Use `.env` at the repo root for local secrets and internal tokens.
`system-secrets.env.local` stores OAuth tokens and system-level defaults (bootstrapped on API startup).
Both files are **never committed**.
Default dev works without a `.env` unless you need private repo access, API keys, or API secrets.

Example:

```bash
EVE_SECRETS_MASTER_KEY=replace-me
EVE_INTERNAL_API_KEY=replace-me
GITHUB_TOKEN=ghp_xxx
```

`create-pr` actions accept `EVE_GITHUB_TOKEN` for PR creation.

## API Secrets

Secrets can be stored at multiple scopes:

- **System**: `/system/secrets`
- **User**: `/users/:id/secrets`
- **Org**: `/orgs/:id/secrets`
- **Project**: `/projects/:id/secrets`

Resolution order (highest wins): **project → user → org → system**.

System secrets are loaded from `system-secrets.env.local` on API startup; restart the API to pick up changes.

Values are never returned in plaintext. The `show` endpoint returns a fixed
mask (`••••••••`, never a character of the value), the value's `length`, and a
`fingerprint`: 12 hex of an HMAC over the scope, key and value, under a key
derived from the master key. Two secrets with the same fingerprint at the same
scope and key hold the same value; the fingerprint says nothing across scopes,
keys or instances.

## Storage at rest

Secret values are encrypted with AES-256-GCM under `EVE_SECRETS_MASTER_KEY`.
Integration tokens (`integrations.tokens_json`) and OAuth app client secrets
(`oauth_app_configs.client_secret`) are covered too.

| Format | What it is |
|---|---|
| `v1:iv:tag:data` | A secret encrypted with no associated data. |
| `v2:iv:tag:data` | A secret encrypted with associated data `scope_type\|scope_id\|key`: it opens only in its own row. Integration tokens and client secrets use the same envelope with `table\|id\|field`. |
| plain | Integration tokens and client secrets before re-encryption. |

Every release from 0.1.327 reads all three. New writes stay `v1` (and plain
for the OAuth columns) until a system admin runs the re-encryption command,
so a rollback to a release that reads only `v1` stays possible until then:

```bash
eve system secrets reencrypt --dry-run   # count rows by format; change nothing
eve system secrets reencrypt             # attended; cannot be rolled back
```

The command sets the instance setting `secrets.ciphertext_format` to `v2`
(new writes use `v2`: at once on the API that ran it, within half a minute on
the others), then re-encrypts `v1` secrets and plain OAuth columns in batches.
Each row is swapped by compare-and-set on the value read: a row written while
the pass runs keeps its new value, and the report counts it; run the command
again to take it. Rows the master key cannot open are counted and left; set
them again. **After the command, a release below 0.1.327 cannot read the
re-encrypted rows.** Run it only once the release has soaked.

The instance rule `secrets.legacy_ciphertext` records each read of a `v1`
secret or a plain OAuth column under `audit`, and refuses it under `strict`
(where writes also use `v2`). Setting the instance `strict` is refused (409,
with the count) while any `v1` or plain rows remain; `--force` overrides, and
the audit log records the count it was forced with.

## Import secrets from a file (CLI)

You can attach a batch of secrets to a scope from an env-style file (KEY=VALUE lines):

```bash
# secrets.env
Z_AI_API_KEY=...
GITHUB_TOKEN=ghp_xxx

# Import into an org (shared across projects)
eve secrets import --org org_xxx --file ./secrets.env

# Import into a project
eve secrets import --project proj_xxx --file .env
```

Notes:
- Supported scopes: `--project`, `--org`, `--user`, `--system` (admin only).
- Lines starting with `#` are ignored; blank lines are ignored.
- Values are read verbatim after `=` (quotes are not stripped).
- Imports upsert each key as `env_var`.

## Manifest Requirements + Validation

Manifests can declare required secrets via `x-eve.requires.secrets` (top-level)
and step-level `requires.secrets`. These are validated on demand:

```bash
eve project sync --validate-secrets
eve project sync --strict
eve secrets validate --project proj_xxx
```

Validation reports missing secrets with scope-aware remediation hints
(`eve secrets set ... --scope project|org|user|system`).

## Safe Secrets (Ensure + Export)

Certain secrets are safe to auto-generate and export for configuring external systems.
Currently allowlisted:

- `GITHUB_WEBHOOK_SECRET`

Generate if missing and export:

```bash
eve secrets ensure --project proj_xxx --keys GITHUB_WEBHOOK_SECRET
eve secrets export --project proj_xxx --keys GITHUB_WEBHOOK_SECRET
```

`ensure` returns each value it generates once, in its own response
(`values`); the CLI prints it. Export returns the plaintext value (for webhook
setup). Treat both as sensitive.

Under a project's `strict` profile, rule `secrets.value_read`, secret values
are write-only through the API: export gets 403, and the value of a safe
secret is seen only in the `ensure` that creates it. `eve github setup`
returns the webhook secret only when it creates it (or with `--regenerate`);
otherwise `secret` is `null`. Under `audit`, each export is recorded.

## Manifest Secrets Interpolation

Environment variable values in `eve.yaml` manifests support `${secret.KEY_NAME}` syntax for secret interpolation during deployment.
The same placeholder syntax is supported in job `env_overrides`: agent jobs,
workflow `script`/`run` steps, and pipeline `action: { type: run }` steps
resolve placeholders at execution time before launching the harness or bash
process. Missing referenced secrets fail fast with `missing_secret_override`;
`eve job show --json` still returns the raw unresolved placeholder text.

### Syntax

```yaml
services:
  api:
    environment:
      DATABASE_URL: postgres://user:${secret.DB_PASSWORD}@db:5432/mydb
      API_KEY: ${secret.EXTERNAL_API_KEY}
  db:
    environment:
      POSTGRES_PASSWORD: ${secret.DB_PASSWORD}
```

### Local Secrets File

For development, create `.eve/dev-secrets.yaml` in your project to provide local secrets (normally gitignored).
(`.eve/secrets.yaml` is deprecated but still supported as a fallback.)

```yaml
# .eve/dev-secrets.yaml
secrets:
  # Default secrets (fallback for any environment)
  default:
    DB_PASSWORD: dev_password

  # Environment-specific overrides
  test:
    DB_PASSWORD: test_password
  staging:
    DB_PASSWORD: staging_password
  production:
    DB_PASSWORD: ${REQUIRE_REAL_SECRET}  # Placeholder - set via API
```

**Resolution order**: API secrets → overlaid by local `.eve/dev-secrets.yaml`

Local secrets take precedence for developer convenience. This allows checking in safe dev defaults while production uses API secrets.

### K8s Deployments

For k8s deployments, local `.eve/dev-secrets.yaml` **only works** when:
- The project uses a `file://` repo URL pointing to a local path
- The worker has filesystem access to that path (e.g., host-mounted volume)

**For production k8s deployments**, set secrets via the API instead:

```bash
# Set project-level secret
eve secrets set POSTGRES_PASSWORD mypassword --scope project --project proj_xxx

# Set org-level secret (applies to all projects in org)
eve secrets set POSTGRES_PASSWORD mypassword --scope org --org org_xxx
```

This ensures secrets are stored securely and accessible to workers running in containers.

### Example Repo

The [eve-horizon-fullstack-example](https://github.com/eve-horizon/eve-horizon-fullstack-example) demonstrates this pattern with a checkable `.eve/dev-secrets.yaml` file.

## Worker Injection

- Resolved secrets are injected as environment variables for the worker and deployer (allowlisted). 
- File and `ssh_key` secrets are written **outside** the repo workspace and are **not** available to agent processes.
- The worker no longer writes `.eve/secrets.env` into the workspace and does **not** set `EVE_SECRETS_FILE`.
- Optional hooks still run in the worker context, but only see the allowlisted environment variables.

## Agent Secrets Allowlist

An agent job receives every secret it resolves unless an allowlist applies.
Two places declare one:

| Where | Field | Applies to |
| --- | --- | --- |
| `agents.yaml` | `agents.<id>.access.secrets: [NAME, ...]` | Every job the agent runs, however it was started, including a job in another project of the org routed to it by `target.agent_slug` |
| Workflow agent step | `secrets: [NAME, ...]` | That step's job (stored on the job as `secrets_allowlist`) |

When both apply, the job receives only names both lists contain. Names match
the secret key in any scope (system, org, user, project); the usual
precedence picks the value. `[]` means no secrets; an absent field means no
restriction. Both execution paths (agent runtime and worker) apply the list
before anything reaches the harness: env vars, file secrets, Claude/Codex auth
selection, workspace hooks and `env_overrides` interpolation.

Not affected: the job token and app-link variables (platform credentials, not
secrets), and the workspace clone, which may still use a git credential the
list leaves out (see below). Script and `run` steps never receive secrets
except through their declared `env_overrides`.

The orchestrator resolves the effective list into the invocation; the attempt
log records the names kept, any named but missing, and how many were withheld
(lifecycle `secrets` / `secrets_allowlist`).

**Agent jobs a restricted job starts directly stay restricted.** The job
token minted for a job with an effective allowlist carries it as a
`secrets_allowlist` claim. Jobs that token creates (`POST /jobs`, batches,
workflow runs and retries, pipeline runs, environment deploys, chat routes and
thread continuations) are stamped with it, narrowed by any step list; a job it
edits, releases to run (`POST /jobs/{id}/release`), or rejects in review is
narrowed to it, under a row lock. On these routes a list only ever narrows.
The job's `secrets_allowlist` is shown on job responses and is never set by
clients.

The stamp restricts **agent** jobs only. Script and `run` steps and pipeline
actions (builds, deploys, `run` actions) ignore it: they resolve their declared
`env_overrides` from every project secret. A restricted job that may start a
pipeline or a workflow with script steps (`pipelines:write`,
`workflows:write`, `envs:write`; none is a default agent permission) reaches
the secrets those steps name. Do not grant those permissions to an agent with
an allowlist.

**What an allowlist does not do on a shared pod.** By default
(`EVE_AGENT_RUNTIME_EXECUTION_MODE=inline`) concurrent agent jobs run inside
one agent-runtime pod as the same user. A restricted job's harness can then
read the environment of a job running beside it (`/proc/<pid>/environ`) and
that job's secret folders (`$TMPDIR/eve/job-secrets/<attempt>`,
`$TMPDIR/eve/git-keys/<attempt>`, `$TMPDIR/eve/agent-homes/<attempt>`). The
allowlist limits what the job is handed, not what it can reach on a shared
pod. A shared inline pod runs other projects' jobs too, and other orgs' jobs
unless the deployment dedicates runtimes to one org (for example with
`EVE_ORG_ID`), so moving the agent to its own project does not separate it.
For an agent that reads untrusted input, run agent jobs in runner-pod mode
(`EVE_AGENT_RUNTIME_EXECUTION_MODE=runner`: one job per pod).

A restricted job token also cannot export (`POST /projects/{id}/secrets/export`)
a secret its allowlist leaves out.

App links are project-scoped, not job-scoped: the app-link tokens a job gets
come from `hints.resolved_app_links`, which any `jobs:write` holder in the
consumer project (a restricted job's token included) can edit, so such a
holder can obtain tokens for any of the project's app-link subscriptions. The
allowlist does not limit app links; grant a project only the links all its
agents may use.

**Not covered: work started by events.** An event a restricted job causes is
not stamped, so workflows and pipelines its triggers start are not
restricted. A default agent token can cause such events: posting a thread
message (`threads:write`) emits `chat.message.received`; with more
permissions, `POST /events`, org docs, agent memory and ingest writes emit
others. In a project with a restricted agent, do not declare triggers on
events that agent can cause, or give every agent those triggers run an
allowlist of its own.

**Not covered: what a restricted step hands on.** A restricted workflow step's
output (its result, attachments, thread messages) feeds later steps, which
may be unrestricted. Treat that output as untrusted input in later steps, or
restrict them too.

## Git Auth Injection

- HTTPS clone: `github_token` secrets are injected into the clone URL for private repo access. When a secrets allowlist applies and leaves the token out, the token is not put in the clone URL (where it would persist in `.git/config`); the clone sends it as an auth header from its environment instead.
- SSH clone: `ssh_key` secrets are written to a per-attempt key outside the workspace and wired via `GIT_SSH_COMMAND` (`ssh -F /dev/null ... -o UserKnownHostsFile=<per-attempt file> -o StrictHostKeyChecking=accept-new`), so ssh ignores the service user's `~/.ssh/config` and `known_hosts`, which job code can write. Under an allowlist that leaves the key out, the key is deleted once the workspace is prepared. Keys are always deleted when the attempt ends.
- Only git commands that talk to the remote (`clone`, `fetch`, `push`, `pull`, `ls-remote`) get the credential environment; `checkout`, `add`, `commit`, `status` and the rest run without it, since they read repository config the job can write.
- A job whose allowlist leaves the git credential out may not push (`git.push` other than `never`) or reuse a workspace (session mode, or a repo already on disk): both would run a credentialed git command under config the job wrote (a filter driver, `gpg.program`, or `http.proxy` with `sslVerify=false`). They fail fast with `git_credential_not_allowlisted`. The credential "stays out of the job" only on that basis.
- Missing auth now surfaces explicit errors with remediation hints (use `eve secrets set`).

## OAuth Token Management

### Syncing Local Tokens to Eve Secrets

Use `eve auth sync` to register local Claude/Codex OAuth tokens as Eve secrets so agents can use them:

```bash
eve auth sync                      # User-level (default — available to all your jobs)
eve auth sync --org org_xxx        # Org-level (shared across all org projects)
eve auth sync --project proj_xxx   # Project-level (scoped to a single project)
eve auth sync --dry-run            # Preview what would be set without writing
```

This sets `CLAUDE_CODE_OAUTH_TOKEN` (Claude) and `CODEX_AUTH_JSON_B64` (Codex/Code) at the requested scope.

For Codex/Code auth files, `eve auth sync --codex` validates refresh-token usability before writing `CODEX_AUTH_JSON_B64`. If the refresh token has expired or was already used, the command fails before updating Eve secrets and tells you to run `codex login --device-auth`.

### Token Types and Lifetimes

| Token prefix | Type | Lifetime | Recommendation |
|---|---|---|---|
| `sk-ant-oat01-*` | `setup-token` (long-lived) | Long-lived | Preferred for jobs and automation |
| Other `sk-ant-*` | `oauth` (short-lived) | ~15h | Use for interactive dev; regenerate with `claude setup-token` |

`eve auth sync` warns when syncing a short-lived OAuth token. Use `eve auth creds` to inspect token type before syncing. For Codex/Code, `eve auth creds --codex` reports access token validity, refresh token presence/usability, and the `last_refresh` timestamp.

Claude setup-tokens (`sk-ant-oat01-*`) are preferred for managed jobs. At
runtime, `claude`/`mclaude` select secrets by scope specificity
(`project > org > user > system`), then prefer `ANTHROPIC_API_KEY` only within
the same scope. Selected setup-tokens are materialized to an attempt-scoped
`CLAUDE_CONFIG_DIR` under `EVE_JOB_USER_HOME`; conflicting Claude auth env vars
are scrubbed after `env_overrides`, and credential files are never written under
`repoPath`.

Verify the real managed auth path after syncing:

```bash
eve auth verify --harness claude --project proj_xxx --json
eve auth verify --harness codex --project proj_xxx --json
```

The JSON verdict includes `ok`, `secret_key`, `scope_type`, `scope_id`, and
`model_replied`; claude adds `token_class` and `apiKeySource`, codex adds
`source`.

### Automatic Codex/Code Token Write-Back

After each harness invocation, the worker checks if the Codex/Code CLI refreshed `auth.json` during the session. If the token changed, it is automatically written back to the originating secret scope (user/org/project) so the next job starts with a fresh token. This is transparent and non-fatal — a write-back failure logs a warning but does not affect the job result.

### Internal Secret Update Endpoint

The platform exposes `PATCH /internal/secrets/:scope_type/:scope_id/:key` for worker-to-API token write-back. This endpoint:
- Requires `x-eve-internal-token` header (same `EVE_INTERNAL_API_KEY` used by secret resolution)
- Is **update-only** — it will 404 if the secret does not already exist (no create semantics)
- Accepts `{ "value": "..." }` body

## Troubleshooting Secret Resolution

If a job fails during clone or secret resolution:

1. Confirm the secret exists: `eve secrets show <KEY> --project <id>`
2. Ensure `EVE_INTERNAL_API_KEY` and `EVE_SECRETS_MASTER_KEY` are set for API/worker
3. Check orchestrator/worker logs for `[resolveSecrets]` warnings
4. Re-run with corrected secret scope (`project` → `org` → `system`)

## GitHub Private Repos

- `github_token` secrets are used for HTTPS clone.
- `ssh_key` secrets are used for SSH clone (`GIT_SSH_COMMAND` with a temp key).

## Required Config

- `EVE_SECRETS_MASTER_KEY` (API): encryption key for secrets, integration tokens and OAuth client secrets at rest (required to store API secrets). It also keys the mask fingerprint.
- `EVE_INTERNAL_API_KEY` (worker + API): internal token for resolve endpoint (required for API secret resolution).

## Incident Response (Secrets)

If you suspect a secret leak or exposure:

1. **Contain**
   - Rotate the affected secret(s) at the source (GitHub, Slack, cloud provider, etc.).
   - Update the secret via `eve secrets set` or `eve secrets import`.
2. **Invalidate**
   - Restart affected services to flush cached credentials.
   - If a token was printed to logs, assume it is compromised.
3. **Audit**
   - Review recent job logs and pipeline logs for leakage patterns.
   - Check correlation IDs for affected requests.
4. **Recover**
   - Re-run failed jobs or deployments after rotation.
5. **Document**
   - Record what leaked, where it appeared, and why.
   - Add a test or guardrail if the leak was due to missing redaction or RBAC.
