# CI/CD

GitHub Actions workflows for this repo: continuous integration, and the
tag-driven publishing of every release artifact.

> **Canonical repo**: `github.com/eve-horizon/eve-horizon`. Releases are cut here
> and nowhere else. See [OSS Release Cutover](../deploy/oss-release-cutover.md).

## The one rule

**A release tag publishes artifacts. It never deploys.**

This repo builds images and npm packages. Rolling those into a cluster is done
from a *deployment instance repo* by its owner. No workflow here may hold
cluster credentials or use `repository_dispatch` to reach an instance repo — see
[deployment.md](./deployment.md) for the three-repo model.

## Image workflows

| Trigger | Workflow | Result |
| --- | --- | --- |
| PR or main push | `image-build-check.yml` | Builds all seven services and six toolchains without credentials; native source browser smoke |
| `toolchain-images/v*` | `toolchain-images.yml` | Six independently versioned AMD64 GHCR images after archive and native gate |
| `release-v*` | `publish-images.yml` | Seven AMD64 GHCR service images after archive and native gate |
| manual dispatch | either image publisher | Build and native gate only; no publication |

Only publisher jobs have `packages: write` (and `id-token: write` and
`attestations: write`, to sign); a native gate and global
absent-tag check precede them. Release artifacts, digest checks, public
visibility, and owner rollout receipts are specified in
[Container Image Release](../deploy/container-image-release.md). Image releases
use only versioned AMD64 tags, with no AWS mutation or rollout coupling.
Toolchain tags must match `docker/toolchains/release-version.txt`; service
gates resolve that version's Python and browser digests.

The `cli-v*`, `sdk-v*`, and `chat-v*` npm publishers remain. The retired
`worker-images/v*` and `eve-migrate/v*` paths stay retired.

## Release protections

Every tag publisher (`publish-images`, `toolchain-images`, `publish-cli`,
`publish-sdk`, `publish-chat`) works the same way:

1. **Ancestry.** Its first job, `ancestry`, runs
   `scripts/release/ancestry.sh` on a full clone. It fails unless the tagged
   commit is on `origin/main` or on an `origin/hotfix/*` branch. A tag on any
   other commit builds nothing.
2. **Approval.** The publish jobs run in the `release` environment, so they
   wait until a required reviewer approves the run (Actions → the run →
   *Review deployments*). One approval covers all the matrix jobs waiting in
   that run.
3. **Signing** (images only). Each publisher signs the manifest digest it
   pushed with `cosign sign --yes` (keyless: the certificate names this
   repository's workflow and tag, through GitHub's OIDC token) and attaches a
   build provenance attestation (`actions/attest-build-provenance`) to it in
   GHCR. Both are recorded in the public Sigstore transparency log; the
   certificate there names the public repository, workflow, tag and commit.

### Maintainer setup (once, before the next release tag)

These are repository settings; no workflow can create them.

- **Create the `release` environment** (Settings → Environments → New
  environment → `release`) with **Required reviewers** set to the
  maintainers who approve releases. Under *Deployment branches and tags*,
  choose *Selected branches and tags* and add the tag patterns `release-v*`,
  `toolchain-images/v*`, `cli-v*`, `sdk-v*` and `chat-v*`. If the environment
  does not exist when a publish job first runs, GitHub creates it with no
  protection rules, and the job publishes without waiting for anyone.
- **Move `NPM_TOKEN`** from the repository secrets to the `release`
  environment's secrets, so only an approved job can read it.
- **Protect the release tags and hotfix branches** with rulesets that let only
  maintainers create, update or delete tags matching the patterns above and
  branches matching `hotfix/*`. A tag-triggered workflow runs the workflow
  file of the tagged commit, so the ancestry check and the environment bind
  only when the tag itself cannot be pushed by others.

### Hotfix route

To fix a release without taking everything else on `main`:

```bash
git fetch origin --tags
git switch -c hotfix/1.2.4 release-v1.2.3   # branch from the release tag
# fix, or cherry-pick the fix from main, and commit
git push origin hotfix/1.2.4
git tag release-v1.2.4
git push origin refs/tags/release-v1.2.4   # never --tags
```

The ancestry check accepts the tag because its commit is on
`origin/hotfix/1.2.4`; the release then waits for approval and is signed
like any other. Land the same fix on `main` too.

### Verifying an image

Verify by digest, never by tag, with cosign 3.x (the version the workflow
signs with):

```bash
cosign verify ghcr.io/eve-horizon/eve-horizon/api@sha256:<digest> \
  --certificate-identity-regexp '^https://github.com/eve-horizon/eve-horizon/.github/workflows/publish-images.yml@refs/tags/release-v.*$' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

gh attestation verify oci://ghcr.io/eve-horizon/eve-horizon/api@sha256:<digest> \
  --repo eve-horizon/eve-horizon
```

For a toolchain image use `toolchain-images.yml@refs/tags/toolchain-images/v.*`
in the identity. A digest that fails verification was not published by these
workflows from a release tag; do not deploy it.

## Pinned build inputs

`scripts/check-supply-chain.mjs` runs in CI (with its `node --test` spec) and
fails on any Dockerfile `@latest` or npm package without an exact version, any
`FROM` image without an `@sha256:` digest, any action not pinned to a commit
SHA, and any `github`, `inputs`, step-output or job-output expression inside a
`run:` block (pass it through `env:` instead). `tests/manual/**` fixtures are
not checked. To move a pinned input:

- **Harness CLIs**: edit `docker/harness-clis/package.json`, then run
  `npm install --package-lock-only --ignore-scripts` there with npm 11 or later
  and commit both files. `install.sh` installs them with lifecycle scripts off;
  check a new version's install scripts before bumping.
- **Base images**: resolve the tag's multi-arch index digest from the registry
  and update the digest and the tag comment above it.
- **kubectl and crane**: change the version and both sha256 ARGs, from
  `dl.k8s.io/release/<version>/bin/linux/<arch>/kubectl.sha256` and the
  go-containerregistry release's `checksums.txt`, in both the worker and
  agent-runtime Dockerfiles.
- **Actions**: resolve the release tag's commit with
  `git ls-remote https://github.com/<owner>/<repo> 'refs/tags/<tag>*'` (the
  `^{}` line for an annotated tag) and keep the tag in the comment.

## npm packages — the version comes from the tag

`publish-cli`, `publish-sdk` and `publish-chat` all derive the version from the
tag and run `npm version <tag-version>` before publishing. **The `version` field
in `package.json` is ignored**, so the in-repo values drift and are not a
reliable guide to what is published.

Always check npm before tagging. As of 2026-08-25:

| Package | Published | In repo | Next tag must be ≥ |
| --- | --- | --- | --- |
| `@eve-horizon/cli` | `0.2.73` | 0.2.44 | `cli-v0.2.74` |
| `@eve-horizon/auth` + `auth-react` | `0.1.5` | 0.0.1 | `sdk-v0.1.6` |
| `@eve-horizon/chat` + `chat-react` | `0.0.2` | 0.0.1 | `chat-v0.0.3` |

`@eve-horizon/cli@0.2.71` was the first npm release published from the OSS repo.
The current `0.2.73` release was published there on 2026-08-25. `auth`/`chat` are still on
their private-repo versions — the first `sdk-v*`/`chat-v*` tag will be their
first OSS publish.

```bash
npm view @eve-horizon/cli version    # before choosing a tag
```

Tagging a version that already exists fails the publish. Tagging a *lower*
unused version succeeds but moves the npm `latest` dist-tag backwards for every
consumer — worse than a failure, because it's silent.

Publish config was verified on all five packages: none is `private`, each has
`files` and `license: MIT`, and each publishes with `--access public`.

## Installing a published CLI

```bash
npm install -g @eve-horizon/cli            # latest
npm install -g @eve-horizon/cli@0.2.36     # pinned
```

There is also a `/cli-publish-and-install` skill for manual publishing when CI
is unavailable.
