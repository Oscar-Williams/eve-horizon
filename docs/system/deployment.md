# Deployment

> Status: Current
> Last Updated: 2026-11-05

## Purpose

Define the supported deployment configurations and the primary runtime targets for Eve Horizon.

## The three-repo model

Hosted deployments span three repositories. Artifacts flow one way; **the source
repo never deploys.**

| Repo | Role | Owns |
| --- | --- | --- |
| [`eve-horizon/eve-horizon`](https://github.com/eve-horizon/eve-horizon) (this one) | Source | Code; publishes images on `release-v*` |
| [`eve-horizon/eve-horizon-infra`](https://github.com/eve-horizon/eve-horizon-infra) | Public template | Kustomize overlays, Terraform, `bin/eve-infra`, deploy workflow |
| `<org>/<name>-eve-infra` | Private instance | Real hosts, secrets, pinned version, cluster credentials |

```
this repo  ──release-v*──>  public ECR  ──pinned version──>  instance repo  ──deploy-v*──>  cluster
```

A `release-v*` tag here publishes images and stops. Rollouts are triggered only
from a deployment instance repo, by its owner. No workflow in this repo may hold
cluster credentials or dispatch to an instance repo.

**What a cluster actually consumes**: the 7 service images at the pinned
`platform.version`, plus the 5 `toolchain-*` images (independently versioned,
pulled at `latest`). Migrations run from the `api` image. See
[ci-cd.md](./ci-cd.md) for the full artifact inventory and
[oss-release-cutover.md](../deploy/oss-release-cutover.md) for the release
procedure.

## Runtime Modes

Eve Horizon supports two primary deployment modes, controlled by `EVE_RUNTIME`:

| Mode | `EVE_RUNTIME` | Purpose | Runner Execution |
|------|---------------|---------|------------------|
| Docker Compose | `docker` (default) | Quick dev iteration | Local process |
| Kubernetes | `k8s` | Integration testing, manual validation, production | Ephemeral pods |

## Kubernetes (Primary for Testing & Production)

K8s is the **primary deployment target** for integration testing, manual validation, and production workloads.

### Digest-Based Deployments

Deployments support both tag-based and digest-based image references for immutability:

- **Tag-based**: `public.ecr.aws/w7c4v0w3/namespace/service:v1.0.0` (default, traditional)
- **Digest-based**: `public.ecr.aws/w7c4v0w3/namespace/service@sha256:abc123...` (immutable, from pipeline builds)

Release objects capture `image_digests_json` from build outputs, enabling reproducible deployments with exact image pinning.
See [builds.md](./builds.md) for how BuildSpecs/BuildRuns produce artifacts.

### Quick Start

```bash
# Start k3d cluster and apply manifests
./bin/eh k8s start

# Build images and deploy stack
./bin/eh k8s deploy

# Run manual tests (see tests/manual/README.md)
# eve org ensure "manual-test-org" && eve secrets import --org org_manualtestorg --file manual-tests.secrets

# Check status
./bin/eh k8s status
```

### AWS (k3s on VPS)

Production-style AWS deployments use the **`eve-horizon/eve-horizon-infra`** template repo,
which contains the Kustomize overlay, Terraform configuration, and deploy workflow:

- Uses external Postgres (RDS or managed database)
- Assumes images are pulled from public ECR (published by `publish-images.yml` in this repo)
- Sets a placeholder Ingress host and default app domain

The AWS overlay and Terraform have been extracted from this repo. See
[docs/deploy/aws.md](../deploy/aws.md) for the template-based deployment flow.

### Architecture

- **API, Orchestrator, Worker**: Cluster-scoped deployments in the `eve` namespace (worker is not per-env)
- **Postgres**: StatefulSet with 5Gi PVC
- **Runner pods**: Ephemeral pods spawned per job attempt for isolated execution
- **Ingress access**: No port-forwarding needed - access via `http://api.eve.lvh.me`
- **App namespaces**: each environment deploys into `eve-{orgSlug}-{projectSlug}-{envName}`.
  A namespace chosen with `eve env create --namespace` (or an env update) must
  start with the project's prefix `eve-{orgSlug}-{projectSlug}-` and must not be
  another environment's namespace. The deployer labels each namespace with
  `eve.env_id` and refuses to deploy into, or delete, a namespace labelled for
  another environment or one that exists without that label.

### Web Auth Services (Supabase + SSO)

When web auth is enabled, the k8s stack also includes:

- **supabase-auth (GoTrue)** at `auth.<domain>`
- **sso** service at `sso.<domain>`
- **mailpit** at `mail.<domain>` (local-only email capture)
- **auth bootstrap job** to provision the GoTrue database role

Key env vars (API + auth services):

- `SUPABASE_AUTH_URL`, `SUPABASE_AUTH_EXTERNAL_URL`
- `SUPABASE_AUTH_SERVICE_KEY`, `SUPABASE_ANON_KEY`, `SUPABASE_JWT_SECRET`
- `EVE_SSO_URL`, `EVE_AUTH_ADMIN_PASSWORD`

### Runner Pod Reaper

The worker runs a periodic reaper that cleans up orphaned runner pods and PVCs
after job completion. This prevents resource leaks if the worker restarts mid-poll.

Key settings:
- `EVE_RUNNER_REAPER_ENABLED`
- `EVE_RUNNER_REAPER_INTERVAL_MS`
- `EVE_RUNNER_REAPER_GRACE_SECONDS`

### Runner Pods

Job code runs in runner pods that hold no platform credential (no
`DATABASE_URL`, no internal key): the worker prepares each job and posts it to
the pod, which reports with the attempt's job token through
`/jobs/:job/attempts/:attempt/runner/*` on the API. Base sets:

- `EVE_RUNNER_SERVICE_ACCOUNT=eve-runner` on the worker. `eve-runner`
  (`k8s/base/runner-serviceaccount.yaml`) has `automountServiceAccountToken:
  false` and no RoleBinding; never bind a cloud identity to it.
- `EVE_REQUIRE_ENVIRON_PROTECTION=true` on the worker and agent runtime: they
  refuse to start if job processes could read their environment.

Runner pods live in `eve-runners` (`k8s/base/runner-namespace.yaml`: Pod
Security `restricted` enforced, its own `eve-runner` account) and report to
the API's public port by its cluster name (`EVE_API_APP_URL`). The worker
holds a Role there (`k8s/base/runner-rbac.yaml`). `EVE_RUNNER_PODS_ONLY=true`
puts every project's job code in runner pods for a migration window.

**agent-sandbox** is optional and is not installed by base. Where the
instance overlay installs it (pinned release manifest, `agent-sandbox-config`
allow-listing the `eve.horizon` label domain), the worker renders the
runner templates and warm pools and claims runner pods from them; set
`runner.runtime_class`, `runner.warm_pool.chat` and `runner.warm_pool.job`
with `eve system settings set`, then run `eve system security reconcile`.
Without it, runner pods are created directly. See
[runner pods](runner-pods.md#backends-agent-sandbox-or-a-plain-pod).

### Secrets Provisioning

All secrets are managed through a system-level flow:

1. **System secrets**: Define secrets in `system-secrets.env.local`
   - Example: `GITHUB_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`
2. **Sync to K8s**: Run `./bin/eh k8s secrets` to sync `system-secrets.env.local` + auth-derived keys to the `eve-app` secret
3. **Restart consumers**: Restart deployments that consume `eve-app` (`eve-api`, `eve-orchestrator`, `eve-worker`) so updated env values are loaded
4. **API reads**: API reads system secrets as baseline

This provides a consistent baseline for all environments without manual patching or org-specific hacks.

### Ingress Routing

Deployed apps are accessible via Ingress with automatic URL generation:

```
URL pattern: {component}.{orgSlug}-{projectSlug}-{env}.{domain}
Example:     web.acme-fstack-test.lvh.me
```

**Domain resolution order:**
1. Manifest `x-eve.ingress.domain` (if set) - per-app override
2. `EVE_DEFAULT_DOMAIN` env var - cluster-level default
3. No Ingress created (if neither set)

**Local dev:** Uses `lvh.me` which resolves to 127.0.0.1 - no /etc/hosts needed.

**Production VPS:** Set `EVE_DEFAULT_DOMAIN=apps.yourdomain.com` in the worker deployment.

### Reserved Platform Domains

A project cannot claim the platform's own hosts as custom domains, through
`eve domain register` or a manifest's `x-eve.ingress.domains`, and the worker
never renders an Ingress for them. Reserved, each with all its subdomains:

- the hosts of `EVE_API_URL`, `EVE_PUBLIC_API_URL`, `EVE_SSO_URL` and
  `SUPABASE_AUTH_EXTERNAL_URL`, plus `EVE_REGISTRY_HOST` and
  `EVE_PLATFORM_INGRESS_HOSTNAME` (always);
- every domain in `EVE_RESERVED_DOMAINS` (comma-separated, optional).

If DNS has an apex or wildcard record for the platform's parent domain pointing
at the shared ingress, set `EVE_RESERVED_DOMAINS=yourdomain.com` on both the API
and the worker, so no tenant can claim any host under it (for example a future
platform host). Hosts under `EVE_DEFAULT_DOMAIN` keep their existing handling:
`eve domain register` refuses them and deploys skip them in favour of an ingress
alias. Manifest sync rejects a reserved custom domain with a 400 naming the
manifest path; a deploy that still carries one (claimed before this check
existed) logs a warning, skips it and garbage-collects its old Ingress.

### Ingress Timeouts and Body Size

Tenant HTTP ingresses support two controller-agnostic knobs under
`x-eve.ingress`:

```yaml
x-eve:
  ingress:
    public: true
    port: 3000
    timeout: 600s
    max_body_size: 100m
```

`timeout` sets nginx `proxy-read-timeout` and `proxy-send-timeout` for every
Ingress rendered for that service (default host, alias, and custom domains).
`max_body_size` sets nginx `proxy-body-size`. Platform defaults are
`EVE_DEFAULT_INGRESS_TIMEOUT=300s` and
`EVE_DEFAULT_INGRESS_MAX_BODY_SIZE=10m`; manifest values override them. Valid
ranges are `1s`-`30m` and `1k`-`1g`.

Phase 1 emits L7 tuning annotations only when `EVE_DEFAULT_INGRESS_CLASS` is
`nginx` or `nginx-ingress`. Other controllers keep routing unchanged; explicit
tenant tuning logs a warning. Confirm the live values with:

```bash
eve env diagnose <project> <env>
eve env diagnose <project> <env> --json | jq '.http_ingress'
```

### Internal API Port

The API's `/internal/*` routes are for platform services, authenticated by
`EVE_INTERNAL_API_KEY`. Without `EVE_API_INTERNAL_PORT` they share the public
port with every other route, so the ingress exposes them. Set it on `eve-api`
to take them off the public port (`k8s/base` does, with `4791`):

- The API also listens on `EVE_API_INTERNAL_PORT` (for example `4791`). That
  port serves every route, `/internal/*` included.
- On the public port (`API_PORT`), `/internal/*` answers `404`, the same as a
  route that does not exist. The check uses the route the request resolved to
  and the port the connection arrived on, so encoded paths and forged headers
  do not get round it.
- `/internal/registry/token` stays on the public port: it is the registry's
  token realm, which BuildKit and kubelet on every node follow.

Turning it on is one change across several workloads; do it in a single
rollout, or in-cluster calls to `/internal/*` fail:

1. `eve-api`: set `EVE_API_INTERNAL_PORT` and add the port to the `eve-api`
   Service (not to the Ingress).
2. Point `EVE_API_URL` at the internal port on the platform services that
   call `/internal/*`: `eve-orchestrator`, `eve-worker`, `eve-agent-runtime`,
   `eve-gateway` and `eve-sso` (for example
   `http://eve-api.eve.svc.cluster.local:4791`). Set `EVE_API_APP_URL` on the
   worker to the public port (default
   `http://eve-api.eve.svc.cluster.local:4701`): apps and runner pods get that
   as their `EVE_API_URL`, never the worker's own, so they never hold the
   internal port. An app keeps the URL it was deployed with until its next
   deploy.
3. Leave `eve-dashboard` on the public port. Its server proxies browser
   requests under `/api/*` to `EVE_API_URL`, so pointing it at the internal
   port would publish `/internal/*` through the dashboard host. (For the same
   reason, an ingress rule that blocks `/internal` on the API host alone does
   not cover the dashboard host; this port split does. The dashboard server
   also answers `404` itself for `/api/internal` and anything under it, in
   any spelling, and for any `/api` path with a `..` segment.)
4. Where NetworkPolicies restrict traffic to `eve-api`, allow the internal
   port from the platform services only. Eve's own egress policies
   ([egress policies](egress-policies.md)) allow apps and runner pods the
   public port (4701) alone, so `/internal/*` is out of their reach even with
   a stolen key.

In `k8s/base` (and so the local k3d stack from `./bin/eh k8s deploy`) this is
already done: `eve-api` sets `EVE_API_INTERNAL_PORT=4791`, the `eve-api`
Service carries an `internal` port, `eve-cluster-config`'s `EVE_API_URL` is
`http://eve-api:4791` and its `EVE_API_APP_URL`
`http://eve-api.eve.svc.cluster.local:4701`, and the dashboard sets
`EVE_API_URL=http://eve-api:4701` inline. To reach `/internal/*` from a workstation, port-forward
`svc/eve-api 4791`. A deployment that takes its manifests from elsewhere needs
steps 1-4 itself.

Unset (the API's default), nothing changes. Docker compose, local pnpm dev and
`eve local` (the CLI's bundled manifests) leave it unset.

### Ingress TLS (Apps)

App ingresses can be issued TLS certificates automatically via cert-manager.

**Recommended (cert-manager):**
- `EVE_DEFAULT_TLS_CLUSTER_ISSUER=letsencrypt-prod`
- Optional: `EVE_DEFAULT_INGRESS_CLASS=traefik` (or your ingress class)

When `EVE_DEFAULT_TLS_CLUSTER_ISSUER` is set, app ingresses include a `tls` block
and cert-manager annotations so certificates are issued per host.

**Wildcard cert (optional):**
- `EVE_DEFAULT_TLS_SECRET=wildcard-apps-tls`

If you provide a wildcard cert, the worker will reference that secret name in every
app ingress. Ensure the secret exists in each app namespace.

### App Node Placement

On managed Kubernetes the worker can pin every app pod it creates (service
Deployments and `x-eve.role: job` service Jobs) to a dedicated node pool. Set
on the worker:

| Variable | Meaning |
| --- | --- |
| `EVE_APP_PLACEMENT_ENABLED` | `true` to apply placement. Off by default. |
| `EVE_COMPUTE_MODEL` | Placement applies only for `gke`, `eks` and `aks`. |
| `EVE_APP_NODE_SELECTOR_KEY` / `_VALUE` | Node label the pods must match (`nodeSelector`). |
| `EVE_APP_TAINT_KEY` / `_VALUE` | Taint on the pool; pods get a matching toleration (`Exists` when no value). |
| `EVE_APP_TAINT_EFFECT` | `NoSchedule` (default), `PreferNoSchedule` or `NoExecute`. |

Placement is opt-in because infrastructure templates set the selector and taint
variables before anything read them: turning it on moves running apps onto the
app pool (often spot capacity) at their next deploy, so make sure the pool
exists and can scale first. Settings that cannot be honoured (placement enabled
on `k3s`, an incomplete selector, an unknown taint effect) are logged as worker
warnings at each deploy. Services with `x-eve.networking.egress: stable` keep
their egress-pool placement instead. Pipeline and agent runner pods are not
app workloads and are not affected.

### Manifest Variable Interpolation

Environment values in manifests support variable interpolation:

| Variable | Replaced With | Example |
|----------|---------------|---------|
| `${ENV_NAME}` | Environment name | test, staging, production |
| `${PROJECT_ID}` | Project ID | proj_01kfew... |
| `${ORG_ID}` | Organization ID | org_Example... |
| `${ORG_SLUG}` | Organization slug | acme, example-org |
| `${COMPONENT_NAME}` | Current service name | api, web, db |
| `${SSO_URL}` | Platform SSO broker URL | `https://sso.eve.example.com` |
| `${secret.KEY}` | Secret value | `${secret.DB_PASSWORD}` |
| `${managed.<service>.<field>}` | Managed DB value (when provisioned) | `${managed.db.url}` |

Example manifest:
```yaml
services:
  api:
    image: public.ecr.aws/w7c4v0w3/org/api
    ports: [3000]
    environment:
      DATABASE_URL: postgres://eve:eve@${ENV_NAME}-db:5432/eve
```

### Platform-Injected Environment Variables

The deployer automatically injects these variables into all deployed service containers:

| Variable | Description |
|----------|-------------|
| `EVE_API_URL` | Internal cluster URL for server-to-server calls |
| `EVE_PUBLIC_API_URL` | Public ingress URL for browser-facing apps (when configured) |
| `EVE_SSO_URL` | SSO broker URL for user authentication (when configured) |
| `EVE_PROJECT_ID` | Current project ID |
| `EVE_ORG_ID` | Current organization ID |
| `EVE_ENV_NAME` | Current environment name |

Services can override these values by defining them explicitly in their `environment` section. Use `EVE_API_URL` for backend calls and `EVE_PUBLIC_API_URL` for browser/client-side code.

For adding SSO login to deployed apps using these variables, see [App SSO Integration](./app-sso-integration.md).

### Service Secrets

Credentials never sit in a Deployment or Job spec, on every security profile.
At each deploy the deployer writes one Opaque Secret per service,
`<env>-<service>-eve-secrets` (labelled `eve.service_secrets=true`), holding:
- every `environment` value that references `${secret.KEY}` or
  `${managed.*}`, after interpolation;
- `EVE_SERVICE_TOKEN` and app-link `*_TOKEN` values.

The container reads each of them through `valueFrom.secretKeyRef` under the
same env var name, so apps see no change. Plain values stay inline.

- **Rolling on change:** the pod template carries `eve.secrets-sha256`, a
  SHA-256 over the Secret's keys and values, so a changed secret value rolls
  the pods at the next deploy. (Every deploy mints a new service token, so
  every deploy rolls the pods, as before.)
- **Pruning:** after a deploy, Secrets of this env's services that were not
  rendered are deleted, but only once the Deployment they were written for
  is gone: Eve does not delete the Deployment of a service dropped from the
  manifest, and its pods could not restart without their Secret.
- **Service jobs** (`x-eve.role: job`, migrations) read their values from a
  Secret made for the run (`<env>-<job>-eve-secrets`, labelled
  `eve.job_secrets=true`) and removed when the run ends.
- **First deploy after the upgrade:** values move from the Deployment into
  the Secret in that deploy's normal rolling update, with the same values.
- **Rollback to an older release:** an older deployer renders the values
  inline again and ignores these Secrets; they stay in the namespace until
  a newer deployer prunes them or the env is deleted.

### Worker Rights

The worker holds two ClusterRoles (`k8s/base/worker-rbac.yaml`):

- `eve-worker-namespaces`, bound cluster-wide: namespaces (get, list,
  watch, create, patch, delete; labels merge with a patch, so no `update`),
  RoleBindings (create, get, list, delete) and `bind` on the ClusterRole
  `eve-worker-tenant` alone. Nothing on Secrets or workloads.
- `eve-worker-tenant`, never bound cluster-wide: pods, Services,
  ConfigMaps, Secrets, PVCs, Deployments and the other workloads, Jobs,
  Ingresses, NetworkPolicies and GKE FQDNNetworkPolicies. The worker binds
  it (RoleBinding `eve-worker-tenant`) in each namespace it creates or
  adopts; the template binds it in `eve` and `eve-runners`.

Every namespace the worker creates carries `eve.horizon/managed=true`. At
start-up the worker labels and binds the env namespaces earlier releases
created (they carry `eve.env_id`) when that label names a live environment
whose namespace it is and the namespace is under the project's prefix
(`eve-<org>-<project>-`); others are left alone and logged. An env whose
stored namespace predates the prefix rule is not adopted: move it under the
prefix (or bind `eve-worker-tenant` there by hand) before the old
`eve-worker` ClusterRole goes.

The template's ValidatingAdmissionPolicy `eve-worker-namespace-guard`
(`k8s/base/worker-admission-policy.yaml`, Kubernetes 1.30 or later) refuses
the worker's service account:

- writes of namespaced objects outside managed namespaces and `eve`,
  `eve-runners` and `eve-builds`, and any cluster-scoped write but
  namespaces;
- creating a namespace without the managed label; changing a namespace that
  has neither that label nor `eve.env_id`; deleting one without the label,
  or a static one;
- a RoleBinding (created or deleted) to any role but `eve-worker-tenant`, or
  for any subject but the worker.

`tests/k8s/worker-guard.kind.sh` runs each allowed and refused write on a
kind cluster as the worker (`kubectl --as`).

Other templates: an overlay that sets one `namespace:` for every object
moves `eve-worker-tenant-runners` into the platform namespace; apply the
runner namespace's objects from their own kustomization, as for the runner
policies. The `aws-nlb` TCP ingress check reads
`deployment/aws-load-balancer-controller` in `kube-system`; with no rights
there it logs that it could not check and goes on.

**Rollout (0.1.328):** apply the new ClusterRoles and bindings (the old
`eve-worker` ClusterRole and ClusterRoleBinding stay for now), deploy the
worker and wait for its log line "Managed namespaces reconciled", apply the
admission policy, then delete `clusterrole/eve-worker` and
`clusterrolebinding/eve-worker`. **Rollback:** re-apply the previous
template, which brings back `eve-worker` with its all-namespace rights,
and delete the admission policy (an earlier worker creates namespaces
without the managed label, which the policy refuses). The labels,
`eve-worker-tenant` and its RoleBindings stay, unused and harmless.

### Pod Security

Under the project's `strict` profile (rule `isolation.pod_security`), tenant
pods and service job pods run with the restricted Pod Security context and a
numeric user from `x-eve.security.run_as_user` or the image's numeric `USER`
(read with `crane config`, using the env's pull credentials). A strict deploy
whose service has neither is refused before anything is applied, naming the
fields; see [manifest](manifest.md#x-evesecurity). The namespace gets the
Pod Security `warn` and `audit` labels (`restricted`, or `baseline` after an
opt-out); `enforce` comes from the rule `isolation.pod_security_admission`
below. Under `audit` and `legacy` pod specs are unchanged;
`audit` records each service's image user and what `strict` would add.

Under the rule `isolation.pod_security_admission` (rule set 3) a strict
deploy sets `warn` and `audit` at the namespace's level before the workloads,
and `pod-security.kubernetes.io/enforce` at that level only once the
rollout has succeeded, so pods of the old release that do not meet it are
never refused when a node is replaced. The level is the least of every
service's, service jobs included (`restricted`, or `baseline` once a service
or a job such as a migration opts out with `run_as_root` or a capability).
`enforce-version` is pinned to `EVE_POD_SECURITY_VERSION` on the worker
(`v1.<minor>`, default `v1.30`, the oldest minor Eve's admission policies
support; set it to the cluster's minor), never `latest`, so a cluster
upgrade does not tighten running namespaces. Eve marks the namespace
`eve.horizon/pod-security-enforce` when it sets `enforce`.

- A rollout that fails or does not finish leaves `enforce` as it was; the
  next successful deploy sets it. A failure to set it after the rollout is
  logged.
- When a release lowers the level (a new opt-out), an `enforce` Eve set is
  lowered before the workloads, so the new pods are admitted.
- Under `audit` the namespace carries `warn` and `audit` only. Under `audit`
  and `legacy` an `enforce` Eve set (marked) is removed at the next deploy;
  one Eve did not set stays.

Labels are written only when they differ. Under `strict` a failure to set
the labels before the workloads stops the deploy. Each `audit` and `strict`
deploy is recorded with the env and level.

### Load Balancer Recovery

k3d's load balancer can become stale after sleep/wake cycles. The `k8s.sh` script auto-recovers:

```bash
# Manual recovery if needed
docker restart k3d-eve-local-serverlb
```

See [k8s-local-stack.md](./k8s-local-stack.md) for detailed k8s documentation.

## Runner and Toolchain Images

Platform releases publish one versioned `worker` service image alongside the
other six services:

```text
public.ecr.aws/w7c4v0w3/eve-horizon/worker:<platform-version>
```

Deployment instances pin that image as both the worker deployment image and
`EVE_RUNNER_IMAGE`. Language and media tooling is materialised separately from
`toolchain-{python,media,rust,java,kotlin}` images using
`EVE_TOOLCHAIN_IMAGE_PREFIX` and `EVE_TOOLCHAIN_IMAGE_TAG` on worker and
agent-runtime pods. Toolchains have their own release line; they are not
`worker-full` variants.

Production instances must pin the seven service images to one release version.
Do not use `worker-full`, `worker-python`, or other `worker-*` variant names:
those images never became a supported public release surface.

### Image Pull Authentication

ECR images are public by default. For private deployments:

**Kubernetes**:
Create an image pull secret:
```bash
kubectl create secret docker-registry ecr-pull-secret \
  --docker-server=public.ecr.aws/w7c4v0w3 \
  --docker-username=<registry-username> \
  --docker-password=<registry-password> \
  --namespace=eve
```

Reference in deployment:
```yaml
spec:
  imagePullSecrets:
  - name: ecr-pull-secret
```

**Docker Compose**:
Login to a private registry before starting the stack:
```bash
echo $REGISTRY_PASSWORD | docker login public.ecr.aws/w7c4v0w3 -u <registry-username> --password-stdin
docker compose up
```

## Docker Compose (Quick Dev Loop)

Docker Compose is optimized for **fast local iteration** during development.

**Security note:** Docker Compose is dev-only. It exposes services on localhost and uses simple defaults. Do not run it in shared or internet-exposed environments.

### Quick Start

```bash
# Start the stack
./bin/eh start docker
```

### When to Use

- Daily development with frequent code changes
- Quick iteration without k8s overhead
- Running integration tests locally (stub harness by default)

### Comparison

| Aspect | Docker Compose | K8s (k3d) |
|--------|----------------|-----------|
| Startup time | ~10s | ~60s |
| Resource usage | Lower | Higher |
| Production parity | Moderate | High |
| Runner pods | No (local process) | Yes (ephemeral pods) |
| Primary use | Daily dev, quick iteration | Integration, manual validation, production |

## macOS Local Development

- **Prereqs**: Docker Desktop (8GB+ memory, 4+ CPUs), Node.js, pnpm
- **K8s extras**: k3d, kubectl
- **Local config**: `.env` for secrets, `system-secrets.env.local` for auth keys, `.eve-horizon.yaml` for ports

## Runtime Environment Variables (Key)

All platform services:
- Internal service keys. `EVE_INTERNAL_CORE_KEY` on `eve-api`,
  `eve-orchestrator`, `eve-worker` and `eve-agent-runtime`;
  `EVE_INTERNAL_GATEWAY_KEY` on `eve-gateway` only; `EVE_INTERNAL_SSO_KEY` on
  `eve-sso` only; `EVE_INTERNAL_DELIVER_KEY` on `eve-api` only (sent to the
  gateway with deliveries); `EVE_INTERNAL_CALLER_HASHES`
  (`core:<sha256>,gateway:<sha256>,sso:<sha256>,deliver:<sha256>`) on
  `eve-api` and `eve-gateway`. The worker and agent runtime refuse every
  request except `GET /health` without a key, and refuse to start without one
  when `NODE_ENV=production`. Runner pods get only the core key's hash.
- `EVE_INTERNAL_API_KEY`: the legacy shared key, still sent and accepted
  beside the keys above until it is removed. See
  [auth.md → Internal Service Authentication](./auth.md#internal-service-authentication)
  and [security profiles](./security-profiles.md#internal-service-keys).
- `EVE_REGISTRY_CREDENTIAL_KEY` on `eve-api` and `eve-worker` only: signs
  registry credentials ([container registry](./container-registry.md#credential-key)).

Each platform service takes only the `eve-app` keys it reads, by
`secretKeyRef` (base `k8s/base/*-deployment.yaml`), never the whole Secret by
`envFrom`; the gateway and the SSO get no database URL and no core key. The
refs are optional, as `envFrom` was, so a key missing from the Secret leaves
the variable unset rather than stopping the pod; except
`EVE_REGISTRY_CREDENTIAL_KEY`, which the API and the worker require (it may be
empty), so they never start on different registry keys.

Orchestrator:
- `ORCH_LOOP_INTERVAL_MS`
- `ORCH_CONCURRENCY`
- `ORCH_CONCURRENCY_MIN` / `ORCH_CONCURRENCY_MAX`
- `ORCH_TUNER_ENABLED`
- `ORCH_TUNER_INTERVAL_MS`
- `ORCH_TUNER_CPU_THRESHOLD`
- `ORCH_TUNER_MEMORY_THRESHOLD`
- `EVE_WORKER_POLL_INTERVAL_MS`
- `EVE_AGENT_RUNTIME_POLL_INTERVAL_MS`
- `EVE_ORCH_RECOVERY_INTERVAL_TICKS`
- `EVE_ORCH_STALE_RECOVERY_INTERVAL_TICKS`
- `EVE_ORCH_STALE_RUNNING_SECONDS`
- `EVE_ORCH_STALE_IDLE_SECONDS`
- `EVE_ORCH_TIMEOUT_GRACE_SECONDS`
- `EVE_ORCH_ATTEMPT_STALE_MINUTES`

Worker:
- `EVE_EGRESS_FQDN_PROVIDER`: `gke` to enforce `x-eve.egress.hosts` with GKE
  FQDNNetworkPolicies, `none` (default) for no enforcement; see
  [egress policies](./egress-policies.md#host-allow-lists).
- `EVE_RUNNER_REAPER_ENABLED`
- `EVE_RUNNER_REAPER_INTERVAL_MS`
- `EVE_RUNNER_REAPER_GRACE_SECONDS`

API mailer / SES feedback (only meaningful when `GOTRUE_SMTP_HOST` is `*.amazonaws.com`; see [auth.md → Mail Delivery and SES Suppression](./auth.md#mail-delivery-and-ses-suppression)):

| Variable | Default | Notes |
| --- | --- | --- |
| `EVE_MAILER_CHECK_SUPPRESSION` | `auto` | `auto` = enabled when SMTP host is SES; `true`/`false` force override. Set `false` for Mailpit / local dev. |
| `EVE_MAILER_SES_REGION` | parsed from `GOTRUE_SMTP_HOST` | Region for `GetSuppressedDestination` (e.g. `us-west-2`). Falls back to host parsing for `email-smtp.<region>.amazonaws.com`. |
| `EVE_SES_CONFIGURATION_SET` | — | Sent as `X-SES-CONFIGURATION-SET` header on every outbound mail so SES routes Bounce/Complaint/Delivery/Reject events to the SNS topic. |
| `EVE_SES_FEEDBACK_TOPIC_ARN` | — | Topic ARN allowed to POST to `/webhooks/ses-feedback`. Mismatches are rejected — protects against spoofed SNS payloads. |

For the AWS EKS overlay, the API pod's IRSA role must include `ses:GetSuppressedDestination`. This is granted in `deployment-instance-repo` under `terraform/aws/modules/ses-feedback`. The mailer fails open on any AWS error other than `NotFoundException`, so a missing or broken IRSA never blocks delivery for unsuppressed addresses — but it will spam `mailer.suppression_check_failed` log lines until fixed.

## Production Deployment

Production uses Kubernetes (k3s or managed k8s):

- **Platform images**: Pin all seven service images, including `worker`, to the
  same release version. Use the separate toolchain-image prefix/tag settings
  for on-demand language and media tooling.
- **ConfigMaps/Secrets**: Environment configuration and credentials.
  Each platform service gets its internal key (see above); probes stay on
  `GET /health`, which needs no credentials.
- **Persistent volumes**: Database and workspace storage
- **RBAC**: Worker service account permissions (pods, PVCs, services CRUD)
- **Manifests**: Same base manifests as local k3d with production-specific overlays

See [worker-types.md](./worker-types.md) for details on worker image variants, routing configuration, and adding custom worker types.

## Workspace Janitor (Disk Safety)

Workspace reuse and session workspaces require active disk management in production.

Recommended operator controls:
- `EVE_WORKSPACE_MAX_GB`: total workspace budget per instance
- `EVE_WORKSPACE_MIN_FREE_GB`: hard floor; refuse new claims if below
- `EVE_WORKSPACE_TTL_HOURS`: idle TTL for job worktrees
- `EVE_SESSION_TTL_HOURS`: idle TTL for session workspaces
- `EVE_MIRROR_MAX_GB`: cap for bare mirrors

Policies:
- LRU eviction of worktrees when over budget.
- TTL cleanup for idle job/session worktrees.
- Mirror maintenance via `git fetch --prune` and periodic `git gc --prune=now`.
- Emit system events on low disk; do not start new attempts when below minimum free space.

K8s notes:
- Per-attempt PVCs are deleted after completion.
- Session-scoped PVCs should have TTL cleanup and storage quotas.

## Diagnosing a Failed Deploy

Since the deploy-error-surfacing work (releases post 2026-04-21) a failed deploy
should give you a structured answer without reaching for `kubectl`.

**Step-by-step:**

1. `eve pipeline logs <pipeline> <run-id>` — the top of the output includes a
   `Failure:` block with the `DeployFailure` kind, the affected service/pod, and
   a `Next step` hint.
2. `eve env show <project> <env>` — when the DB and cluster have diverged (for
   example a partially applied manifest) the output shows `Current Release`
   marked `(last ready)` and `Last Applied` marked `DRIFT — cluster differs from
   last-ready`, plus the failure kind on `Last Failure`.
3. `eve job diagnose <job-id>` — works for any job; renders the same
   `DeployFailure` block with a pod snapshot.
4. `eve env diagnose <project> <env>` — live K8s view (pods, events, readiness).
5. `eve env logs <project> <env> <service> --previous` — previous-container log
   excerpt. The CLI hint in the `app_crash_loop` path links here directly.

For a request-specific incident after the app is running, prefer the request
diagnose and trace commands:

```bash
eve env diagnose <project> <env> --request req_01h... --window 120 --json
eve env logs <project> <env> <service> --follow --filter req_id=req_01h...
eve traces query --project <project> --request-id req_01h... --json
```

### TCP Ingress Diagnostics

`eve env diagnose <project> <env>` includes a `TCP Ingress` table when a
service declares `x-eve.tcp_ingress`. The JSON shape is available at
`.tcp_ingress[]` and reports each service, provider, advertised host, external
LoadBalancer address, listener port, listener state, and local node target port
when Kubernetes allocates one.

Listener states mirror the live LoadBalancer service:

| State | Meaning |
|-------|---------|
| `pending` | Manifest opts in but the `eve.tcp_ingress=true` Service is absent. |
| `provisioning` | Service exists but `status.loadBalancer.ingress[]` is still empty. |
| `ready` | Kubernetes reports an external hostname or IP. |

Probe a ready listener from the operator machine:

```bash
eve tcp-ingress test <project> <env> --listener a1-gt06
eve tcp-ingress test <project> <env> --listener a1-gt06 --timeout 10 --json
```

This is a TCP connect probe only; it does not speak the device protocol. For
local k3d, raw TCP ports must be mapped into the cluster load balancer at
creation time:

```bash
./bin/eh k8s start --tcp-ports 33400,33500 --recreate
```

**DeployFailure kinds** (see `apps/worker/src/deployer/deploy-failure.ts`):

| Kind | Typical cause | Next step |
| --- | --- | --- |
| `k8s_api_error` | Platform API issue | Share `attempt_id` with Eve support. |
| `manifest_invalid` | Invalid YAML or schema rejected by K8s | `eve manifest validate`. |
| `image_pull_error` | Bad image digest or missing `imagePullSecret` | `eve env diagnose`. |
| `app_crash_loop` | App process exits on start | `eve env logs <svc> --previous`. |
| `readiness_timeout` | Pods up but not passing readiness probes | `eve env diagnose`. |
| `dependency_timeout` | `depends_on` service didn't become healthy | `eve env logs <dep>`. |
| `ingress_conflict` | Another env already owns the hostname | `eve domain list` + `eve domain transfer`. |

## Custom Domain Ownership

Custom domains can be declared at `services.<svc>.x-eve.ingress.domains` or in
environment overrides at
`environments.<env>.overrides.services.<svc>.x-eve.ingress.domains`.
`eve project sync` registers manifest-managed domains. A domain declared in
exactly one environment override is bound to that environment during sync, so
the first deploy of that env can render its Ingress without a wrapper script.

Custom domains are owned by **exactly one environment at a time**. Top-level
domains keep first-bind-wins behavior: the first env to deploy with the
hostname owns it. Subsequent deploys of other envs that reference the same
hostname log `owned by environment "<A>" — skipping` and leave the owning env's
ingress alone. Imperative reservations use:

```bash
eve domain register api.example.com --project <project> --service api --env staging
```

`eve domain status api.example.com --json` exposes stable `owner_env`,
`dns_state`, `cert_state`, and `last_verified_at` fields for scripts.

To move ownership deliberately:

```bash
eve domain list                                       # see hostname → env mapping
eve domain transfer api.example.com --to staging      # DB-only ownership move
eve env deploy production                             # removes stale ingress from losing env
eve env deploy staging                                # creates new ingress in new owner's ns
```

`eve domain unbind <hostname>` clears the env binding without picking a new
owner — the next deploy that declares the hostname claims it.

## Manifest Resolution for Deploys

`eve env deploy --ref <sha>` resolves the pipeline's manifest from the ref:

1. If the ref has been previously synced (`eve project sync --ref <sha>` or an
   earlier deploy of that ref), the pipeline run binds to that ref's manifest.
2. Otherwise it falls back to the project's latest manifest AND the worker's
   post-clone check compares the workspace's expanded manifest hash with the
   pipeline's frozen hash. Workflow `$ref` entries and `agent.prompt_file`
   prompts are expanded before hashing, matching `eve project sync`.
3. On mismatch the deploy fails with `ManifestDrift` and a
   `Run \`eve project sync --ref <sha>\` from a checkout of that ref` hint —
   no silent stale deploys.

## Legacy / Removed

- None.
