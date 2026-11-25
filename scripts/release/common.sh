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
# Runner pods start tini, the entrypoint shell and node with the worker image's
# non-dumpable preload (docker/worker/eve-nodump.c), because gVisor cannot load
# execute-only binaries. With it, each process's /proc/<pid>/environ is owned by
# root; without it, by the process's user. Both runs are checked, so a probe
# that cannot tell them apart fails too.
release_check_worker_nodump() {
  local ref=$1 preloaded plain err
  # shellcheck disable=SC2016 # expanded by the container's shell
  local probe='stat -c %u /proc/1/environ /proc/$$/environ && exec /usr/local/bin/node -e "console.log(require(\"fs\").statSync(\"/proc/self/environ\").uid)"'
  local limit=()
  command -v timeout >/dev/null && limit=(timeout 120)
  # Only stdout is compared: a pull note or a daemon warning on stderr must not
  # fail a good image. --init=false keeps tini as PID 1 whatever the daemon's
  # default.
  err=$(mktemp)
  preloaded=$(${limit[@]+"${limit[@]}"} docker run --rm --network none --user 1000:1000 --init=false \
    -e LD_PRELOAD=/usr/local/lib/eve/eve-nodump.so --entrypoint /usr/bin/tini "$ref" -- /bin/bash -c "$probe" 2>"$err") \
    || release_die "worker image did not run with the runner preload: $preloaded $(cat "$err")"
  plain=$(${limit[@]+"${limit[@]}"} docker run --rm --network none --user 1000:1000 --init=false \
    --entrypoint /usr/bin/tini "$ref" -- /bin/bash -c "$probe" 2>"$err") \
    || release_die "worker image did not run: $plain $(cat "$err")"
  rm -f "$err"
  [[ $(printf '%s' "$preloaded" | tr '\n' ' ') == '0 0 0' ]] \
    || release_die "runner preload did not make tini, bash and node non-dumpable: $preloaded"
  [[ $(printf '%s' "$plain" | tr '\n' ' ') == '1000 1000 1000' ]] \
    || release_die "cannot tell a dumpable process from a non-dumpable one: $plain"
  echo "qualified worker image $ref: runner preload makes tini, bash and node non-dumpable"
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
