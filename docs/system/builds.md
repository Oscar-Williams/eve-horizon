# Builds (First-Class Primitive)

> Status: Current
> Last Updated: 2026-01-31
> Purpose: Document BuildSpecs, BuildRuns, and BuildArtifacts as first-class primitives.

## Overview

Builds are now explicit system primitives, independent of pipelines and jobs.
They provide a stable record of what was built (spec), how it was built (run),
and what was produced (artifacts). Releases reference `build_id` and derive
image digests from artifacts for deterministic deploys.

## Core Concepts

### BuildSpec
Immutable input defining *what* to build.

Fields:
- `project_id`, `git_sha`, `manifest_hash`
- `services` (subset of manifest services)
- `inputs`, `registry`, `cache`

### BuildRun
Execution instance defining *how* and *where* a build ran.

Fields:
- `build_id`, `status`, `backend`
- `runner_ref`, `logs_ref`, `error_message`
- `started_at`, `completed_at`

### BuildArtifact
Output record defining *what* was produced.

Fields:
- `service_name`, `image_ref`, `digest`
- `platforms`, `size_bytes`
- `sbom_ref`, `provenance_ref` (reserved)

## API

```
POST /projects/{project_id}/builds        # create BuildSpec
GET  /projects/{project_id}/builds        # list BuildSpecs
GET  /builds/{build_id}                   # BuildSpec detail
POST /builds/{build_id}/runs              # create BuildRun
GET  /builds/{build_id}/runs              # list BuildRuns
GET  /builds/{build_id}/artifacts         # list BuildArtifacts
GET  /builds/{build_id}/logs              # stream BuildRun logs
POST /builds/{build_id}/cancel            # cancel latest or specified run
```

## CLI

```
eve build create --project <id> --ref <sha> --manifest-hash <hash> [--services <list>] [--repo-dir <path>]
eve build list [--project <id>]
eve build show <build_id>
eve build run <build_id>
eve build runs <build_id>
eve build logs <build_id> [--run <id>]
eve build artifacts <build_id>
eve build diagnose <build_id>
eve build cancel <build_id>
```

## Build Backends

`EVE_BUILD_BACKEND` selects `buildx` (alias `docker`), `buildkit`,
`kaniko`, or `sandbox`. An unset value defaults to Buildx locally and
BuildKit in Kubernetes. Unknown values are rejected. There is no automatic
fallback from BuildKit to Kaniko.

### Disposable rootless BuildKit (unreleased)

`sandbox` creates a new `SandboxClaim` for each service image build, runs
`buildctl` on the worker against that claim's verified pod IP, then deletes
the claim with foreground cleanup. The worker clones the repository and
sends a temporary context snapshot through the BuildKit session. The snapshot
excludes `.git` directories, and its context and Dockerfile must resolve
inside the checkout and context respectively. Registry auth stays
in a mode-0600 temporary Docker config on the worker and is removed after
success, failure or cancellation; no git or registry Secret is mounted in
the builder pod.

The instance rule `builds.isolated` requires this backend under `strict`.
Other backends are refused before resolving registry auth. Under `audit`,
the same choice records a finding and remains usable. Selecting `sandbox`
also stops reuse of build results produced by another backend.

Deployment owners provision the `eve-builds` namespace, `eve-builder`
SandboxTemplate and a matching SandboxWarmPool with **replicas: 0**, using
agent-sandbox's `extensions.agents.x-k8s.io/v1beta1` API. The worker refuses
a nonzero pool. Install this release and the matching infrastructure before
selecting `sandbox`; releases through 0.1.332 do not provide it.

| Worker variable | Default | Purpose |
|---|---|---|
| `EVE_BUILD_SANDBOX_NAMESPACE` | `eve-builds` | Isolated builder namespace |
| `EVE_BUILD_SANDBOX_TEMPLATE` | `eve-builder` | Matching pool and template name |
| `EVE_BUILD_RUNTIME_CLASS` | `gvisor` | Required runtime of the claimed pod |
| `EVE_BUILD_SANDBOX_IMAGE` | Pinned rootless BuildKit v0.34.1 digest | Must match the template and admission policy |
| `EVE_BUILD_READY_TIMEOUT` | `5m` | Bound cold startup, including node scale-up |
| `EVE_BUILD_TIMEOUT` | `30m` | Bound claim creation, startup and build session together |

Timeouts accept a positive integer followed by `ms`, `s` or `m`, at most
24 hours. The claim also has a deletion deadline for worker crashes.
Job cancellation and `eve build cancel` are polled during builds; cleanup
uses its own bounded signal. A cleanup failure fails the build even if the
image was pushed, and the claim name is logged for the operator.

The template must use user/group 1000, `runAsNonRoot`, a digest-pinned
rootless image, `--oci-worker-no-process-sandbox`, an appropriate runtime
class, tokenless service account and emptyDir state. Rootless BuildKit
requires Unconfined seccomp/AppArmor: namespace admission must confine that
exception to the builder image/runtime and refuse privileged containers,
host namespaces, host paths, added capabilities and injected credentials.
Network policy admits the worker on TCP 1234 only, and allows DNS, public
image/package sources and the instance registry while excluding metadata,
the Kubernetes API and private networks. The worker needs create/get/delete
on claims, get on the named pool, and get/list on pods; no exec, Secret or
template-write rights.

`EVE_BUILDKIT_ADDR` and `BUILDKIT_HOST` apply only to the shared `buildkit`
backend; sandbox never falls back to either. `EVE_BUILDKIT_CACHE_REPO`
enables the registry cache. An Eve registry cache remains under the
project's prefix; external-registry sandbox builds use a project-specific
`eve-cache-<project-id>` tag on the authorized image repository. Local
BuildKit state is discarded with each pod.

## Release Integration

- Release creation accepts `build_id`
- Image digests are derived from BuildArtifacts
- Deploys use digest-based image references for immutability

## Validation & Errors

- `manifest_hash` must match the synced manifest for the project ref
- Releases require a valid `build_id` that exists for the project
- Mismatches surface explicit errors; re-run build or re-sync the manifest

## Diagnostics

Use `eve build diagnose <build_id>` to pull spec, runs, artifacts, and recent logs
in one command.

## Observability

### Build Logs

```bash
eve build logs <build_id>              # Timestamped build output
eve build logs <build_id> --run <id>   # Specific run's logs
```

Each log line is prefixed with `[HH:MM:SS]` timestamps for easy correlation.

### Build Diagnosis

```bash
eve build diagnose <build_id>          # Full state: spec + runs + artifacts + logs
```

Shows:
- Build spec (git SHA, manifest hash, services)
- All runs with status, backend, timestamps
- Build artifacts (images, digests)
- Recent logs (last 50 entries)
- **Error classification** with actionable hints

### Error Codes

When builds fail, errors are classified automatically:

| Code | Label | Hint |
|------|-------|------|
| `auth_error` | Authentication Error | Check GITHUB_TOKEN via `eve secrets set` |
| `clone_error` | Git Clone Error | Verify repo URL and access |
| `build_error` | Build Error | Run `eve build diagnose <build_id>` for full output |
| `timeout_error` | Timeout Error | Check resources and timeouts |
| `resource_error` | Resource Error | Check disk space and memory |
| `registry_error` | Registry Error | Check registry credentials |

### BuildKit Output

Build failures include the last 30 lines of buildkit output and identify the failed Dockerfile stage:

```
Error: buildctl failed with exit code 1 at [build 3/5] RUN pnpm install
--- Last 12 lines ---
#8 [build 3/5] RUN pnpm install --frozen-lockfile
#8 ERROR: process "pnpm install --frozen-lockfile" did not complete successfully
...
```

### Pre-Build Visibility

Clone, checkout, and workspace preparation phases now produce observable log entries, visible through `eve build logs` and `eve job diagnose`.

## Related

- [pipelines.md](./pipelines.md)
- [container-registry.md](./container-registry.md)
