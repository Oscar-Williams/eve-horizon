# Runner pods

> **Status**: current. Applies to agent jobs the worker runs, script steps
> with `EVE_SCRIPT_K8S_RUNNER=true`, and the agent runtime's runner mode.

A runner pod runs one job attempt and holds **no platform credential**: no
`DATABASE_URL`, no internal key (nor its hash), no forwarded `EVE_WORKER_*`
or `EVE_HARNESS_*` settings, no service account token. The worker does every
database and internal-API call the job needs, sends the result to the pod,
and the pod reports back only through push-only routes, with the attempt's
own job token.

```
orchestrator ── POST /invoke ──▶ worker (outer)
                                  │ 1. prepare: DB reads, bound secret resolve,
                                  │    job token, app-link tokens, presigned URLs
                                  │ 2. create the runner pod (inbound key hash in its env)
                                  │ 3. POST /runner/submit  (x-eve-runner-key)
                                  ▼
                               runner pod ── job token ──▶ API /jobs/:job/attempts/:attempt/runner/*
                                  │                         logs, events, runtime-meta,
                                  │                         thread-messages, credential, result
                                  ▼
                worker records the attempt once the result exists AND the pod has ended
```

## The runner entrypoint

The runner image is the worker image; the pod starts
`/usr/local/libexec/eve-node --disable-sigusr1 dist/runner/main.js` through
the image's `tini` and entrypoint script. `RunnerModule`
(`apps/worker/src/runner/`) loads no database module and none of the
deployer, builder, reaper or pipeline modules. It serves two routes:

| Route | Purpose |
|---|---|
| `GET /health` | Answers from the process alone (readiness). |
| `POST /runner/submit` | Takes one job (`RunnerSubmit`, `packages/shared/src/invoke/runner-protocol.ts`). A second submit gets 409. |

The submit is authenticated with a key made for that pod: the worker
generates 32 random bytes, puts only their SHA-256 in the pod's env
(`EVE_RUNNER_INBOUND_KEY_SHA256`), and presents the key in
`x-eve-runner-key`. The runner compares hashes in constant time. A pod
started from a warm pool cannot carry per-job env; with no hash it takes the
first submit that carries a key, which is all a one-job pod ever takes.

The runner reports its result, then exits (`EVE_RUNNER_SELF_TERMINATE=1`),
so the pod ends `Succeeded`.

## The submit body

The worker prepares everything:

| Field | What the worker resolved |
|---|---|
| `job_token` | The attempt-bound job token (minted with the agent's own `access.permissions` as the agent runtime mints them, or the step's token permissions and scope). The job uses it; the runner reports with it. |
| `agent.invocation` | The effective invocation: manifest default env applied, app CLIs resolved. |
| `agent.secrets` / `script.secrets` | The job's bound secrets (below). |
| `git_ref` | The job's ref under its `ref_policy` (env release SHA, manifest ref or project default). |
| `resources` | Resource refs: org documents and job attachments inline, ingest files as presigned GET URLs (15 min). |
| `chat_attachments` | Chat files as presigned GET URLs. |
| `context_files` | The rendered `.eve/` context: coordination inbox, thread history, carryover (`agent_context`). The runner writes only paths under `.eve/`. |
| `app_apis` | App APIs and app links, each link's token already minted for the attempt. |
| `budget` | The budget enforcement config (rate card, FX, resource class). |
| `relay` | The job's and parent's hints and the threads they name, for the message relay. |
| `script.*` | For a step: command, timeout, repo, env name and namespace, env overrides and the reserved-name decision, app-link env, toolchains. |

## Secrets

The worker asks the API for the job's **bound** set
(`POST /internal/projects/:id/secrets/resolve` with `job_id`, `harness` and
`bound: true`):

- user secrets resolve for the job's own actor (unless the job may resolve
  none); a `user_id` in the request is ignored;
- a job with an allowlist (agent `access.secrets`, step `secrets:`) gets those
  keys only;
- an unbound job gets everything under `legacy` and `audit` (recorded under
  `audit`), and under `strict` only its harness credential and the keys its
  env overrides reference (`secrets.unbound_job`);
- the clone credential (GitHub token or SSH key for the project's repo) comes
  flagged `clone_only` when the binding leaves it out.

A `clone_only` credential is used for the workspace clone and the platform's
own git policy calls, as an auth header (never in the clone URL, so never in
`.git/config`). `selectJobSecrets` drops it before the harness starts, and a
job that would need it after the clone (push, a reused workspace) is refused.

A script step's bound set is the keys its env overrides reference, plus the
clone credential (flagged `clone_only` in a runner pod unless the overrides
reference it).

## Push-only routes

All under `/jobs/:job_id/attempts/:attempt_id/runner/`, each with
`Authorization: Bearer <job token>`. The token must be a job token bound to
the attempt in the path, and stops working when that attempt ends (401).
Another attempt's routes get 403. None returns platform data.

| Route | Accepts |
|---|---|
| `logs` | `{ entries: [{ type, content }] }`, up to 500 per call. |
| `events` | `system.resource.hydration.{started,completed,failed}` only, on the job's project. |
| `runtime-meta` | Only `orgfs_mount`, `resource_hydration`, `resource_index_path`, `browser`, `toolchains`, `self_check` (400 otherwise); toolchain image IDs the worker recorded are kept. |
| `thread-messages` | Outbound messages to the job's own chat thread or its parent's coordination thread, only when the thread belongs to the job's project. |
| `credential` | A refreshed `CODEX_AUTH_JSON_B64` only. Accepted when the account claim (`https://api.openai.com/auth`.`chatgpt_account_id`) of its `id_token`, verified against the issuer's published keys (`https://auth.openai.com/.well-known/jwks.json`, or `EVE_CODEX_JWKS_URL`), names the stored credential's account; the plain `account_id` field is ignored. It goes to the secret's own scope, or, under the project's strict `secrets.job_org_write`, to project scope only. A mismatch is refused (409) and logged; the job does not fail. |
| `result` | The attempt's result, once (`job_attempt_runner_results`); a second gets 409. |

Job code holds the same token, so it can push only to its own attempt: it can
forge only its own output, and could under-report its usage (an accepted
residual).

## Recording the attempt

The worker polls for the stored result and the pod's phase. It returns (and
the orchestrator records the attempt) only once the result exists and the pod
has ended. A pod that ends with no result fails the attempt ("Runner pod
ended without a result"); a pod still running `EVE_K8S_RUNNER_RESULT_GRACE_MS`
(default 30 s) after its result is deleted first. The pod is deleted
whatever happens; a cancelled job's pod with a 5 s grace period.

| Setting | Default | Meaning |
|---|---|---|
| `EVE_K8S_RUNNER_POLL_MS` | `2000` | Result and pod poll interval. |
| `EVE_K8S_POLL_TIMEOUT_MS` | `1800000` | How long to wait for a result. |
| `EVE_K8S_RUNNER_RESULT_GRACE_MS` | `30000` | How long a pod may run on after its result. |
| `EVE_K8S_POD_READY_TIMEOUT` | `60s` | How long a pod may take to become Ready. |
| `EVE_API_APP_URL` | `EVE_API_URL` | The API URL a runner reports to (the API's public port when the instance sets one). |

## The pod

One builder (`packages/shared/src/invoke/runner-manifests.ts`) makes every
runner pod: non-root UID 1000, no privilege escalation, every capability
dropped, `RuntimeDefault` seccomp, `enableServiceLinks: false`, no service
account token, and the account from `EVE_RUNNER_SERVICE_ACCOUNT` (base:
`eve-runner`, which has no RoleBinding and no cloud identity). The org
filesystem is mounted only when the job's `orgfs_mount` mode is not `none`,
and read-only unless it is `write`. This narrows the mount; it does not
isolate one org's files from another's.

## The agent runtime

The agent runtime builds no runner pod. In runner mode
(`EVE_AGENT_RUNTIME_EXECUTION_MODE=runner`) it hands the invocation to the
worker (`WORKER_URL` / `EVE_WORKER_URLS`), which prepares and runs it, and
waits for the worker's completion event. Inline mode is unchanged.

## Related

- [security profiles](security-profiles.md)
- [pipelines](pipelines.md#script-execution) for script steps
- [agent sandbox security](agent-sandbox-security.md)
