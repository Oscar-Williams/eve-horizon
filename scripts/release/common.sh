#!/usr/bin/env bash
set -euo pipefail

registry=ghcr.io/eve-horizon/eve-horizon
source_url=https://github.com/eve-horizon/eve-horizon

release_die() { echo "release gate: $*" >&2; exit 1; }
release_version() {
  local value=$1
  [[ $value =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] || release_die "invalid version: $value"
}
release_ref() {
  local kind=$1 name=$2 version=$3
  release_version "$version"
  case "$kind:$name" in
    service:api|service:sso|service:gateway|service:agent-runtime|service:orchestrator|service:worker|service:dashboard|service:migrate) printf '%s/%s:%s\n' "$registry" "$name" "$version" ;;
    toolchain:python|toolchain:media|toolchain:rust|toolchain:java|toolchain:kotlin|toolchain:browser) printf '%s/toolchain-%s:%s\n' "$registry" "$name" "$version" ;;
    *) release_die "unknown release image $kind:$name" ;;
  esac
}
release_native() {
  [[ $(uname -s) == Linux && $(uname -m) == x86_64 ]] || release_die 'native Linux x86_64 host required'
  local daemon
  daemon=$(docker version --format '{{.Server.Os}}/{{.Server.Arch}}')
  [[ $daemon == linux/amd64 || $daemon == linux/x86_64 ]] || release_die "native AMD64 Docker daemon required: $daemon"
}
release_image_id() { docker image inspect --format '{{.Id}}' "$1"; }
release_image_platform() {
  [[ $(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$1") == linux/amd64 ]] || release_die "non-AMD64 image: $1"
}
# Apps run the migrate image as a job, and the strict profile runs it as the
# image's own numeric user: the kubelet cannot check runAsNonRoot against a
# name. Started with no database URL and no network, it must get as far as
# reading its configuration, which proves its code and dependencies load.
release_check_migrate_image() {
  local ref=$1 user output
  user=$(docker image inspect --format '{{.Config.User}}' "$ref")
  [[ $user =~ ^[1-9][0-9]*(:[0-9]+)?$ ]] || release_die "migrate image user must be a numeric non-root uid[:gid]: '$user'"
  # A minute is ample to start and fail; never let a stuck start hold the job.
  local limit=()
  command -v timeout >/dev/null && limit=(timeout 60)
  if output=$(${limit[@]+"${limit[@]}"} docker run --rm --network none "$ref" 2>&1); then
    release_die 'migrate image ran without DATABASE_URL'
  fi
  [[ $output == *'DATABASE_URL environment variable is required'* ]] || release_die "migrate image did not start: $output"
  echo "qualified migrate image $ref user=$user"
}
release_check_tag_absent() {
  local ref=$1 output
  if output=$(docker buildx imagetools inspect "$ref" 2>&1); then
    release_die "version already exists: $ref"
  fi
  # Buildx must identify the requested manifest as missing. Other failures,
  # including a 404 from its token endpoint, cannot prove tag absence.
  case "$output" in
    "ERROR: $ref: not found"|"ERROR: $ref: manifest unknown"|"ERROR: failed to get manifest for $ref: manifest unknown") ;;
    *) release_die "cannot prove unused version $ref: $output" ;;
  esac
}
