# Container Registry

> Status: Current
> Last Updated: 2026-11-05

## Purpose

Documents how Eve Horizon manages container images: registry configuration in manifests, authentication secrets, local development workflows, and how the deployer handles image pulling.

## Current (Implemented)

### Manifest Registry Section

The project manifest (`.eve/manifest.yaml`) includes a `registry` section that configures where images are stored.
It supports three modes: Eve-native (`"eve"`), disabled (`"none"`), or a BYO registry object.

```yaml
registry:
  host: ghcr.io
  namespace: example-org
  auth:
    username_secret: REGISTRY_USERNAME    # Secret key for registry username
    token_secret: REGISTRY_PASSWORD        # Secret key for registry token/password
```

- `host`: The container registry hostname (e.g., `ghcr.io`, `docker.io`)
- `namespace`: The registry namespace/organization (e.g., `example-org`)
- `auth.username_secret`: Name of the secret containing the registry username (defaults to `REGISTRY_USERNAME`)
- `auth.token_secret`: Name of the secret containing the registry token/password (defaults to `REGISTRY_PASSWORD`)

Eve-native and disabled examples:

```yaml
registry: "eve"   # Use Eve-native registry (internal)
registry: "none"  # Skip registry handling
```

### Eve-Native Registry (Internal)

When `registry: "eve"` is set, images are pushed to and pulled from the
platform's registry, which accepts only short-lived JWTs issued by the API
(Docker v2 token auth).

Required system configuration:
- `EVE_REGISTRY_HOST` — registry hostname (e.g., `registry.eve.example.com`)
- `EVE_REGISTRY_SIGNING_KEY` — RSA private key (PEM, `\n`-escaped PEM, base64-encoded PEM, or file path; same loader as `EVE_AUTH_PRIVATE_KEY`, see [auth.md](./auth.md))
- `EVE_BUILDKIT_INSECURE_REGISTRIES` (optional) — comma-separated registry hosts to use with BuildKit insecure/plain-HTTP transport (useful for local in-cluster registries)
- `EVE_BUILDKIT_INSECURE_ALL` (optional) — set to `true` only for local troubleshooting to force insecure transport for all BuildKit registry operations

The signing key is needed on the API only. `EVE_REGISTRY_CREDENTIAL_KEY`, on
the API and the worker only, signs the push and pull credentials described
below (see [credential key](#credential-key)); until it is set,
`EVE_INTERNAL_API_KEY` signs them.

Token endpoint (the registry's token realm, which must stay reachable by
BuildKit and by kubelet on every node):

```
GET  /internal/registry/token?service=eve-registry&scope=repository:<name>:<actions>   (Basic auth)
POST /internal/registry/token                                                          (internal key: x-eve-service-key core)
```

**Image names.** Every image a project builds into the Eve registry lives
under the project's repository prefix, its project id:
`<EVE_REGISTRY_HOST>/<project id>/<image>`. The platform applies the prefix
whatever the manifest says: `image: api`, `image: <EVE_REGISTRY_HOST>/api` and
a build-only service `api` all push to `<host>/proj_.../api`, and the deployer
pulls from the same place. A name that already starts with the project's
prefix is not prefixed twice. Images on other registries (`ghcr.io/...`) are
left as written. The project id is used rather than slugs because it never
changes and is never reused. A `EVE_BUILDKIT_CACHE_REPO` on the Eve registry
becomes one cache per project under the same prefix.

What a token grants depends on who asks. The endpoint grants the permitted
subset of the requested scopes and leaves the rest out (the registry then
refuses that operation):

| Caller | Credential | Granted |
|--------|------------|---------|
| A build (BuildKit or Kaniko) | Basic `eve-push` / project push credential | `pull`, `push` on repositories under `<project id>/` |
| Kubelet in an app namespace | Basic `eve-pull` / environment pull credential | `pull` on repositories under `<project id>/` |
| Internal POST | The core service key (or the legacy key, under `internal.service_key`) | `pull`, `push` on any `repository` scope |
| Operator (legacy) | Basic, `EVE_INTERNAL_API_KEY` as the password | `pull`, `push` on any `repository` scope; refused under `registry.internal_key` `strict` |

Never granted to anyone: `delete`, `*`, and non-repository scopes such as
`registry:catalog:*`. Because the prefix is assigned by the platform, not
chosen by the tenant, one project cannot name its way into another project's
repositories, for push or pull.

**Push credentials.** A build gets
`evepush1.<base64url({"p":"<project id>","exp":<unix seconds>})>.<HMAC>`
(HMAC key derived from the registry credential key by HKDF under its own label),
valid for 6 hours, in place of the internal API key. The build backend's
docker config never holds the internal key, so a Dockerfile `RUN` step that
can read it (Kaniko mounts it at `/kaniko/.docker`) gets at most a short-lived
credential for its own project's repositories.

**Pull secrets.** For each environment the deployer writes an `eve-registry`
pull secret (username `eve-pull`) holding an environment pull credential, not
the internal API key:
`evepull1.<base64url({"p":"<project id>","e":"<environment id>","ns":"<namespace>","n":<epoch>})>.<HMAC>`.
The token endpoint honours it only while:

- the environment still exists, is not terminated, and belongs to the project;
- the project is not deleted;
- the credential's epoch is the environment's current `registry_pull_epoch` or
  the one before. The deployer bumps the epoch each time it rewrites the
  secret (every deploy and every job-service run), so a credential stops
  working two rewrites after it was written. The one-epoch grace covers
  kubelet's secret cache and two rewrites racing.

It has no expiry time of its own, so pods can be rescheduled at any time while
the environment lives.

**Revocation.** Redeploy the environment twice, or delete it, to retire a
leaked pull secret. Rotating `EVE_REGISTRY_CREDENTIAL_KEY` revokes every pull
and push credential at once; run `eve system security reconcile` so every
environment gets a fresh pull credential without a redeploy.

#### Credential key

`EVE_REGISTRY_CREDENTIAL_KEY` (API and worker only) signs registry
credentials, so the key every platform service holds is not also the key to
the registry. Its **version** is 16 hex characters of an HMAC of a fixed label
under the key: it names the key without revealing it. Credentials signed with
`EVE_INTERNAL_API_KEY` have the version `internal`.

Each environment records the version of the key that signed its pull secret,
and the pull epoch it was recorded at (`registry_key_version`,
`registry_key_epoch`), once the secret is written. An environment that has had
an Eve pull secret (`registry_pull_epoch` above 0) is **stale** when its
version is not the current key's, or was recorded at an older epoch (a write
by a release that did not record versions).

`eve system security reconcile` (`POST /system/security/reconcile`) has the
worker go through the stale environments, with no restart:

- an `eve-registry` secret holding an Eve pull credential signed with another
  key, or at another epoch, is rewritten at a new epoch with a credential
  signed with the current key (kubelet reads it at its next pull);
- one already signed with the current key at the current epoch is only
  recorded;
- a namespace with no Eve pull credential (none written, or a bring-your-own
  registry's credentials, which are never touched) is recorded as current.

It reports what it re-signed and what failed; a failed environment stays
stale. `eve doctor security` shows the current version and how many
environments are stale.

The worker writes a pull secret only with the key the API verifies with.
Reconcile sends the API's key version (`registryCredentialKey()`: the
credential key's, or `internal`), and a worker signing with another refuses
with 409 before touching any environment. A deploy asks the API
(`GET /internal/registry/key-version`, core key only) and fails, naming both
versions, rather than write a pull secret the API would refuse. Both read the
key from the same `eve-app` entry, which k8s/base requires (it may be empty),
so they differ only while a change is rolling out.

The token endpoint verifies a credential under the credential key first, then
under the internal key. The internal key itself as a password, and credentials
it signed, follow `registry.internal_key`: accepted under `legacy`, accepted
and recorded under `audit`, refused under `strict`. The instance goes `strict`
only once no environment is stale (409 otherwise, unless `--force`), and the
legacy `EVE_INTERNAL_API_KEY` must stay until then: removing it stops every
credential it signed from verifying.

Upgrading: set `EVE_REGISTRY_CREDENTIAL_KEY` in `eve-app` (read by the API
and the worker; the entry must exist before the upgrade, empty or not), then
restart both: new credentials are signed with it at once, and old ones keep
working. Then run `eve system security reconcile`.

Rolling back to a release that knows only the internal key (0.1.326 and
earlier): it cannot verify credentials the credential key signed. First set
`EVE_REGISTRY_CREDENTIAL_KEY` in `eve-app` to an empty value, restart the API
and the worker, and run
`eve system security reconcile`, which then re-signs every pull secret with
the internal key (version `internal`); then roll back. Keep
`EVE_INTERNAL_API_KEY` set on every service until no rollback below 0.1.327 is
possible.

**Upgrading from un-prefixed images.** Images pushed before project prefixes
(`<host>/<image>`) are outside every project's prefix, so no project
credential can pull them. After upgrading, run each environment's pipeline
(build, release, deploy) once: build reuse ignores builds whose images are
not under the prefix, so the images are rebuilt into it and the deploy pulls
them from there. Deploying an older release by id, without a build, fails
with an image pull error, because its images were never pushed under the
prefix. Until that redeploy, an environment keeps its old `eve-registry`
secret: if it still holds the internal key (written before environment pull
credentials existed), rescheduled pods can still pull their un-prefixed
images; if it already holds an environment pull credential, a pod rescheduled
onto a node without the image cached fails to pull until the redeploy. Once
every environment is redeployed, run `eve system security reconcile` and
retire `EVE_INTERNAL_API_KEY` as [security profiles](security-profiles.md#internal-service-keys)
describes. Old
un-prefixed repositories stay in the registry's storage until removed by hand.

### Service Images

Services specify their full image path without a tag:

```yaml
services:
  api:
    image: ghcr.io/example-org/my-project-api
    build:
      context: ./apps/api
      dockerfile: ./apps/api/Dockerfile
```

The tag is determined by the workflow:
- Local dev: `:local`
- Pipeline builds: Git SHA or version (`:sha-abc123`, `:v1.0.0`)

### Required Secrets

For private registries (including AWS ECR mirrors), add these to `system-secrets.env.local`:

```bash
REGISTRY_USERNAME=your-registry-username
REGISTRY_PASSWORD=your-registry-token
```

**Token requirements:**
- Credentials required by your registry provider for image pushes/pulls.
- Use the corresponding CI/workflow credentials when pushing.

See [secrets.md](./secrets.md) for the full secrets resolution system.

### Deployer ImagePullSecret

When deploying to Kubernetes, the deployer (`apps/worker/src/deployer/deployer.service.ts`) creates an `imagePullSecret` if the manifest has a `registry.host`:

1. Resolves `username_secret` and `token_secret` from the secrets system
2. Creates a Docker config JSON with registry auth
3. Creates/updates a Kubernetes Secret of type `kubernetes.io/dockerconfigjson`
4. Attaches the secret to the deployment's `imagePullSecrets`

If `registry.host` is not set (or `registry: "none"`), no imagePullSecret is created (assumes public images or pre-configured cluster auth).

## Workflows

### Local Development (k3d)

For fast iteration without pushing to a remote registry:

```bash
# Build with :local tag
docker build -t ghcr.io/example-org/my-project-api:local ./apps/api

# Import directly into k3d cluster
k3d image import ghcr.io/example-org/my-project-api:local -c eve-local

# Deploy (requires explicit --ref)
eve env deploy test --ref main --repo-dir .
```

This avoids the push/pull roundtrip to the public registry, making iteration much faster.

### Pipeline Build (Implemented)

When a pipeline runs a `build` action:

1. Creates a BuildSpec (immutable inputs) and BuildRun (execution instance)
2. Executes image builds using Docker Buildx (local) or BuildKit (k8s)
3. Builds the image from the service's `build.context` and `build.dockerfile`
4. Tags with Git SHA or specified version
5. Pushes to `registry.host/registry.namespace/service-name:tag`
6. Captures image digests and stores them as BuildArtifacts (see [builds.md](./builds.md))
7. Release creation references `build_id` and derives digests from artifacts
8. Subsequent `deploy` actions pull from the registry using digest-based references

```yaml
pipelines:
  deploy:
    steps:
      - action: build
        services: [api, web]
        tag: ${GIT_SHA}
      - action: deploy
        env: staging
        services: [api, web]
```

**Build Backend:**
- Local environments: Docker Buildx
- Kubernetes environments: BuildKit (default), Kaniko fallback only if required

**Build reuse (faster local redeploys):**
- Build actions now reuse the most recent successful build artifacts when `project_id + git_sha + manifest_hash + requested services` match.
- Disable reuse per-run by setting action input `force_rebuild: true`.
- Disable reuse globally by setting `EVE_BUILD_REUSE=false` in worker env.

### CI/CD (GitHub Actions)

For CI environments that need explicit registry auth before build:

```yaml
- name: Login to container registry
  uses: docker/login-action@v3
  with:
    registry: ghcr.io
    username: ${{ secrets.REGISTRY_USERNAME }}
    password: ${{ secrets.REGISTRY_PASSWORD }}
```

The Eve worker uses the manifest's `registry.auth` secrets for deployment.

## Planned (Not Implemented)

- Multi-registry support (different registries per component)
- Registry mirroring for air-gapped environments
- Automatic tag cleanup/retention policies

## Related

- [secrets.md](./secrets.md) - Secret storage and resolution
- [deployment.md](./deployment.md) - Kubernetes deployment process
- [k8s-local-stack.md](./k8s-local-stack.md) - Local k3d development setup
