# Runner pods

> **Status**: current. Applies to every agent job the worker runs, script
> steps and `action: run` steps sent to runner pods, and the agent runtime's
> runner mode.

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

The submit presents a key in `x-eve-runner-key`, and the pod holds only its
SHA-256; the runner compares hashes in constant time, and a pod with no hash
takes no submit:

- **a plain pod:** a key made for that pod. The worker generates 32 random
  bytes and puts only their SHA-256 in the pod's env
  (`EVE_RUNNER_INBOUND_KEY_SHA256`);
- **a pod from a warm pool,** which cannot carry per-job env: the worker's
  pool key. Each SandboxTemplate carries its SHA-256
  (`EVE_RUNNER_POOL_KEY_SHA256`). The key is `EVE_RUNNER_POOL_KEY` on the
  worker when set (a Secret value), else an HMAC-SHA256 of the worker's
  internal core key (or the legacy `EVE_INTERNAL_API_KEY`) with a fixed
  label. Job code never sees it: the runner reads it from the request header
  only. A worker with none of them claims no warm pod and renders no
  template.

**Rotating the pool key:** set or change `EVE_RUNNER_POOL_KEY` (or rotate the
core key it is derived from) and restart the worker. At startup (or on
`eve system security reconcile`) it renders the templates with the new hash;
the warm pools (update strategy `Recreate`) then replace their warm pods,
while claimed pods run on. A claim that lands on a warm pod from the older
template before it is replaced is dropped and the job's pod created directly,
so a rotation costs latency, not jobs.

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
| `chat` | For a chat job (label `chat`, a `thread_id` hint): its chat thread, for `eve-message` progress. The final reply is delivered by the orchestrator from the attempt's result text, wherever the job ran. |
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
| `thread-messages` | Outbound messages to the job's own chat thread or its parent's coordination thread, only when the thread belongs to the job's project. With `chat_progress: true`, a chat job's `eve-message` progress, delivered to its chat thread and provider through the same chat delivery the inline path uses; only for a chat job's own chat thread, at most 10 per job and 30 s apart (429 otherwise), 500 characters. |
| `credential` | A refreshed `CODEX_AUTH_JSON_B64` only. Accepted when the account claims (`https://api.openai.com/auth`.`chatgpt_account_id`) of its `id_token` and its `access_token`, each verified against the issuer's published keys (`https://auth.openai.com/.well-known/jwks.json`, or `EVE_CODEX_JWKS_URL`), name the stored credential's account; the access token must not have expired; the plain `tokens.account_id`, when present, must name the same account; and its `OPENAI_API_KEY` must be the stored file's (or absent, as there). The refresh token is opaque and is not checked: a job holds the stored session anyway. It goes to the secret's own scope, or, under the project's strict `secrets.job_org_write`, to project scope only. A mismatch is refused (409) and logged; the job does not fail. |
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
| `EVE_API_APP_URL` | `http://eve-api.eve.svc.cluster.local:4701` | The API URL a runner reports to (as apps do): the API's public port, by a name that resolves from the runner namespace. Never the worker's own `EVE_API_URL`; a single-label host is qualified with the platform namespace. |
| `EVE_RUNNER_NAMESPACE` | `eve-runners` | Where runner pods, templates and claims live. When it does not exist, dispatch fails with "The runner namespace … does not exist" and the k8s/base files to apply. |
| `EVE_SANDBOX_CLAIM_TIMEOUT` | `10s` | How long a claim may take to be Ready before the plain-pod fallback. |
| `EVE_RUNNER_PODS_ONLY` | unset | `true`: every project's job code in runner pods. |

## The pod

One builder (`packages/shared/src/invoke/runner-manifests.ts`) makes every
runner pod: non-root UID 1000, no privilege escalation, every capability
dropped, `RuntimeDefault` seccomp, `enableServiceLinks: false`, no service
account token, and the account from `EVE_RUNNER_SERVICE_ACCOUNT` (base:
`eve-runner`, which has no RoleBinding and no cloud identity). The runner sets
`EVE_REQUIRE_ENVIRON_PROTECTION=true`, so it refuses to start when its
process is dumpable and job processes (the same UID) could read its
environment. The org filesystem is mounted only when the job's `orgfs_mount`
mode is not `none`, and read-only unless it is `write`. This narrows the
mount; it does not isolate one org's files from another's. Pod affinity
(`EVE_RUNNER_POD_AFFINITY_*`) applies only to such a pod, which runs in the
platform namespace beside the pod holding the claim; templates and other
runner pods never carry it.

## Where job code runs (`isolation.runner_mode`)

| Work | `legacy` / `audit` | `strict`, or `EVE_RUNNER_PODS_ONLY=true` |
|---|---|---|
| Agent job | The agent runtime inline when `EVE_AGENT_RUNTIME_URL` is set (recorded under `audit`), else the worker's runner pod | The worker's runner pod; the orchestrator never sends it to the agent runtime |
| Script step | The worker's process, or a runner pod with `EVE_SCRIPT_K8S_RUNNER=true` (inline recorded under `audit`) | A runner pod |
| `action: run` | The worker's process (recorded under `audit`) | A runner pod, through the script handler (checked out at the action's `git_sha`; timeout code `action_run_timeout`) |
| Legacy pipeline-runner `run` step | The worker's process (recorded under `audit`) | Refused: 400, "use a `script:` step" |
| Outside Kubernetes | Inline | Fails: "strict needs runner pods" |

`EVE_RUNNER_PODS_ONLY` is the instance switch for a migration window: every
project gets the strict routing, whatever its profile. It is separate from
`EVE_SCRIPT_K8S_RUNNER`, which still means "scripts in runner pods" only.

Under `strict` a runner pod mounts no org filesystem. Under `legacy` and
`audit` a job whose `orgfs_mount` asks for one runs as a plain pod in the
platform namespace (`EVE_K8S_NAMESPACE`), where the org filesystem claim
lives, with the volume read-only unless the job writes. That is a residual
until each org has its own filesystem (P3): it narrows the mount but does not
isolate one org's files from another's.

### The egress self-check

Before it uses the job token, the runner opens TCP connections to the
metadata server (`169.254.169.254:80`) and the Kubernetes API
(`KUBERNETES_SERVICE_HOST:443`) and reports the result in
`runtime_meta.self_check`. The worker sets the mode in the submit:

| Mode | When | A connection that opens |
|---|---|---|
| `enforce` | the project's profile is `strict` | fails the job: "egress policy not enforced" (`error_code: egress_not_enforced`) |
| `audit` | `audit`, or the instance switch | is recorded; the job runs |
| `off` | `legacy` without the switch | no check |

### Rules a runner applies itself

A runner has no database, so the worker decides the project's profile for
each rule the runner applies (`RUNNER_DECIDED_RULES`, currently
`harness.checkout_settings`) and sends it as `agent.rule_profiles`. The
runner fails rather than skip a rule it was not sent, and records findings
through its events route as `security.finding` (`{ rule, detail }`), which
the API records under the job's project, as the job, for those rules only.

## Backends: agent-sandbox or a plain pod

Runner pods live in their own namespace, `EVE_RUNNER_NAMESPACE` (base:
`eve-runners`, Pod Security `restricted`), apart from the platform's pods.

- **agent-sandbox** (`kubernetes-sigs/agent-sandbox`, v1.0.11): when the
  extension CRDs are served (`extensions.agents.x-k8s.io/v1beta1`, found by
  API discovery) and the job class's warm pool exists with a size above 0, the worker creates a
  `SandboxClaim` on that pool and reaches the pod at
  `status.sandbox.podIPs`. It follows the pod (for liveness) by the
  `eve.horizon/attempt-id` label the claim puts on it, at that IP, never by
  the sandbox's name, and submits only once the label is there. The claim carries the pod labels below through
  `additionalPodMetadata`, no env, and `lifecycle.shutdownTime` (the job's
  timeout plus 15 min) with `shutdownPolicy: Delete`, a safety net if the
  worker dies mid-job. The worker deletes the claim when the job ends.
- **Plain pod**: otherwise, or when a claim is not Ready within
  `EVE_SANDBOX_CLAIM_TIMEOUT` (default `10s`) or fails (`InvalidMetadata`,
  `WarmPoolNotFound` and the like), the worker deletes the claim and creates
  the identical pod directly: same builder, runtime class, security context
  and labels. A controller outage costs latency, never the job. A job with
  init containers (toolchains, app CLIs) or its own resource class always
  gets a plain pod, since a claim cannot vary the pod. `EVE_SANDBOX_BACKEND=off`
  turns the claim backend off.

### Job classes and templates

| Class | Who | Template | Workspace | Warm pool |
|---|---|---|---|---|
| `chat` | jobs labelled `chat` | `eve-runner-chat` (100m/512Mi, limits 1 CPU/2Gi) | `emptyDir` | `runner.warm_pool.chat` |
| `job` | everything else | `eve-runner-job` (`EVE_K8S_RUNNER_*` defaults) | `emptyDir` | `runner.warm_pool.job` |
| `heavy` | a resource class with Kubernetes sizing (job hints or manifest defaults), toolchains or app CLIs | `eve-runner-heavy` (500m/2Gi, limits 4 CPU/8Gi) | a claim of `EVE_K8S_WORKSPACE_SIZE` (default 20Gi; `volumeClaimTemplates`) | always 0 (cold) |

`hints.runner_class` may name a lighter class than the job's (chat, job,
heavy, lightest first), never a heavier one. A class whose warm pool is
sized 0 (heavy always, chat and job by default) is not claimed: the worker
creates its pod directly, rather than wait `EVE_SANDBOX_CLAIM_TIMEOUT` for a
cold claim and then fall back.

The worker renders one `SandboxTemplate` and one `SandboxWarmPool` per class
from its own `EVE_RUNNER_IMAGE` and the instance settings, and applies them in
the runner namespace at startup (so a release's runner image follows the
release) and on `eve system security reconcile` (so changed settings take
effect). Without the CRDs it does nothing. Templates set
`networkPolicyManagement: Unmanaged`: Eve owns runner egress.

| Instance setting | Effect |
|---|---|
| `runner.runtime_class` | `gvisor` sets `runtimeClassName: gvisor`, the node selector `sandbox.gke.io/runtime: gvisor` and its `NoSchedule` toleration on every template and plain runner pod; another value sets the class name only; unset, none. |
| `runner.runtime_class_opt_out` | Classes (comma separated) that run without the runtime class. |
| `runner.warm_pool.chat`, `runner.warm_pool.job` | Warm pool sizes (default 0, at most 50). |

### Runner pod labels

Stable; egress policies select on them.

| Label | On | Value |
|---|---|---|
| `eve.type` | every runner pod | `runner` |
| `eve.horizon/runner` | every runner pod (warm, claimed, plain) | `true` |
| `eve.horizon/job-class` | every runner pod | `chat`, `job` or `heavy` |
| `eve.horizon/project-id` | claimed and plain pods | the project id |
| `eve.horizon/attempt-id` | claimed and plain pods | the attempt id |

A warm pod has only the first three until it is claimed, so egress fails
closed: `eve-runner-deny` (k8s/base) denies every `eve.horizon/runner=true`
pod all but DNS and the API, `eve-runner-ingress` admits only the worker on
the submit port, and each project's policies, written by the worker before it
claims or creates a pod for that project, allow more by
`eve.horizon/project-id` (see [egress policies](egress-policies.md)). The controller's
`agent-sandbox-config` must allow-list the `eve.horizon` label domain, or
every claim fails with `InvalidMetadata` (and falls back to plain pods).

### What the worker may do there

`k8s/base/runner-rbac.yaml`: a Role in the runner namespace with `create`,
`get`, `delete` and `watch` on `sandboxclaims`; `get`, `list`, `create`,
`patch` and `update` on `sandboxtemplates` and `sandboxwarmpools` (to render
them); and pods and claims for the plain fallback. Nothing on `sandboxes`:
only the controller creates them. The reaper scans both namespaces and leaves
pods and claims owned by a `Sandbox` to the controller.

## Differences from the agent runtime's inline path

The worker path matches the inline path for secrets, the job token (with the
agent's `access.permissions`), the job's environment (its `env_name`, then the
manifest default), coordination and thread context, carryover context, chat
attachments, resources, app APIs and links, budgets, usage logs (`llm.call`
lines feed receipts), `eve-message` relay to coordination threads and chat
progress, checkout settings and the final chat reply (delivered by the
orchestrator from the result text). What remains different:

- A runner's workspace lives as long as its pod: a retry clones afresh.
- A job with toolchains or app CLIs gets a cold plain pod with init
  containers, not a warm pod.
- Org files: none under `strict`; under `legacy` and `audit` a plain pod in
  `eve` mounting the shared claim (a `ReadWriteOnce` claim needs pod affinity
  to the node holding it).
- Large inline resources and context files travel in the submit body (32 MB
  limit at the runner).
- Cancellation stops the pod (5 s grace) rather than signalling the harness
  process group in place.

## The agent runtime

The agent runtime builds no runner pod. In runner mode
(`EVE_AGENT_RUNTIME_EXECUTION_MODE=runner`) it hands the invocation to the
worker (`WORKER_URL` / `EVE_WORKER_URLS`), which prepares and runs it, and
waits for the worker's completion event. Inline mode is unchanged.

## Related

- [security profiles](security-profiles.md)
- [pipelines](pipelines.md#script-execution) for script steps
- [agent sandbox security](agent-sandbox-security.md)
