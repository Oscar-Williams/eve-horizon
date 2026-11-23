# Canonical GHCR image release

The seven service packages and the `migrate` image (apps run it as a job to
apply their SQL migrations) live at
`ghcr.io/eve-horizon/eve-horizon/{api,sso,gateway,agent-runtime,orchestrator,worker,dashboard,migrate}`;
the six toolchains use `toolchain-{python,media,rust,java,kotlin,browser}` under
that prefix. Deployment owners roll out digests from their instance repos.

## Release order and gates

1. Review source, the browser decision, `bash scripts/release/check.sh`,
   `pnpm build`, `pnpm test`, and `./bin/eh test integration`. Green source
   checks do not prove the native browser gate or hosted availability.
2. Set `docker/toolchains/release-version.txt` to the approved independent
   toolchain version, currently `0.1.0`. Push only the approved
   `refs/tags/toolchain-images/v<version>` ref. A dispatch runs the same build
   and gate but cannot publish. All six build jobs produce one linux/amd64
   Docker archive plus SHA-256, image ID, source revision and version receipt.
   The native gate loads the exact Python/browser archives, builds worker
   `base` and agent-runtime `production` from that source, and launches the
   bundled Playwright client and Chromium under UID/GID 1000, default seccomp,
   no new privileges, and no capabilities. The probe asserts text, SVG geometry,
   nonempty screenshot, versions, and no cgroup OOM kill at worker 3 GiB and
   agent-runtime 2 GiB. Gate logs are Actions artifacts for 30 days.
3. Only after every build and the native gate pass, `prepublish` checks all six
   version tags are absent. Publisher jobs load their same immutable archives,
   recheck SHA and image/config identity, and push only the versioned tag. No
   release path creates AWS infrastructure or triggers a deployment.
4. Make the six GitHub packages **public** in package settings. A public
   source repository alone does not make its GHCR packages public. Check each
   anonymous digest read from a clean machine/session. Capture package URL,
   tag, manifest digest, config digest, source revision, and gate run ID. If
   a package is private or an anonymous pull fails, stop before service release.
5. Push one approved `refs/tags/release-v<version>` ref. Service builds archive
   all eight exact AMD64 images. The native gate loads the frozen worker and
   agent-runtime images, pulls the declared versioned Python/browser images
   from `release-version.txt`, resolving their registry digests before the
   launch, then loads the frozen migrate image, which must name a numeric
   non-root user and start cleanly with no database. `prepublish` rejects any existing service version tag. Publishers
   wait for approval in the `release` environment, then load, verify and push
   exactly their archived images, and sign and attest each pushed digest. No
   `latest`, `staging`, or SHA alias is part of release qualification. The
   tagged commit must be on `main` or a `hotfix/*` branch; see
   [Release protections](../system/ci-cd.md#release-protections) for the
   ancestry rule, the hotfix route and the one-time `release` environment
   setup.
6. Make all eight packages public (a package's first release creates it
   private), anonymously pull each `@sha256:` digest,
   and inspect source/revision labels and linux/amd64 platform. Record both
   manifest and config digests; the publisher verifies config identity against
   the local image ID. `cosign verify` each digest against the
   `publish-images.yml` identity
   ([Verifying an image](../system/ci-cd.md#verifying-an-image)).
7. The deployment instance owner pins those service and toolchain **digests**,
   reviews their instance Terraform/manifests, performs the rollout there, and
   records deployment revision, actual pulled imageIDs, job IDs, browser
   versions, DOM/SVG result, and screenshot SHA-256. Hosted BR-08 and capacity
   checks occur only after that rollout. Attach those receipts to issue #6.

Push only `refs/tags/<approved-tag>` to `origin`, never `--tags`. A partial
publish consumes that version; resolve it and choose a new version rather than
overwrite tags.

## Capacity and provenance

Per-image jobs run on native GitHub `ubuntu-24.04` x64. The service gate loads
the worker, agent-runtime and migrate archives and two toolchains. Locally,
compressed worker/agent-runtime archives were about 2.1/1.86 GB (migrate is
under 0.1 GB); measure the first hosted run against its 14 GB
disk and use a larger native x64 runner if needed. Do not prune an operator's
local Docker daemon.

Actions v4 archives are immutable within a run. Receipts carry SHA-256 and
image ID; publishers verify those, OCI labels, platform, and registry config
digest. The browser probe copies payloads into the qualified runtime bases.
Registry digests prove input provenance, not integrity of files in a writable
runtime toolchain cache.
