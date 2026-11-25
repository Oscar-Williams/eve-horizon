#!/usr/bin/env bash
# Checks that the worker entrypoint installs nothing at start. The harness
# variants (mclaude, zai) are built into the image; one that is missing is
# reported and that harness is unavailable. Nothing is fetched over the
# network into a container that holds the worker's secrets, and no program a
# job could have planted is run.
# Run: bash docker/worker/entrypoint.test.sh
set -euo pipefail

# The entrypoint needs bash >= 4.4 (empty arrays under set -u), as in the image.
if (( BASH_VERSINFO[0] < 4 || (BASH_VERSINFO[0] == 4 && BASH_VERSINFO[1] < 4) )); then
  echo "SKIP: needs bash >= 4.4, found $BASH_VERSION" >&2
  exit 0
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# $tmp/trusted stands in for the image's root-owned /usr/local/bin. Each
# installer there only records that it ran.
mkdir -p "$tmp/trusted" "$tmp/home/.local/bin"
for tool in cc-mirror npx npm; do
  printf '#!/bin/sh\necho "%s $*" >> "%s/calls"\n' "$tool" "$tmp" > "$tmp/trusted/$tool"
  chmod +x "$tmp/trusted/$tool"
done

export HOME="$tmp/home"
# The job PATH the container starts with. Only system tools besides the test
# dirs: a cc-mirror or npx installed on the host must not count.
export PATH="$tmp/home/.local/bin:/usr/bin:/bin"
export Z_AI_API_KEY="zai-key"
# shellcheck disable=SC1091
EVE_ENTRYPOINT_FUNCTIONS_ONLY=1 source "$here/entrypoint.sh"
[[ "$SERVICE_JOB_PATH" == "$tmp/home/.local/bin:/usr/bin:/bin" ]] || { echo "FAIL: job PATH not kept" >&2; exit 1; }
# The entrypoint switched its own PATH to root-owned directories; point that
# at the stand-in so no host installer can run.
PATH="$tmp/trusted:/usr/bin:/bin"

fail() { echo "FAIL: $*" >&2; exit 1; }

# 1. Both variants missing: each is reported, and nothing is installed.
declare -F report_missing_variants >/dev/null || fail "the entrypoint has no report_missing_variants"
report_missing_variants 2> "$tmp/log"
sleep 0.5
grep -q "mclaude is not in this image; the mclaude harness is unavailable" "$tmp/log" \
  || fail "missing mclaude not reported: $(cat "$tmp/log")"
grep -q "zai is not in this image; the zai harness is unavailable" "$tmp/log" \
  || fail "missing zai not reported: $(cat "$tmp/log")"
[[ ! -e "$tmp/calls" ]] || fail "an installer ran at start: $(cat "$tmp/calls")"

# 2. A variant in the image is not reported.
printf '#!/bin/sh\nexit 0\n' > "$HOME/.local/bin/mclaude"
chmod +x "$HOME/.local/bin/mclaude"
report_missing_variants 2> "$tmp/log"
grep -q "mclaude" "$tmp/log" && fail "mclaude reported although it is in the image"
grep -q "zai is not in this image" "$tmp/log" || fail "missing zai no longer reported"
[[ ! -e "$tmp/calls" ]] || fail "an installer ran at start: $(cat "$tmp/calls")"

# 3. No install path is left in the entrypoint.
if grep -nE '(^|[^[:alnum:]_-])npx([^[:alnum:]_-]|$)|cc-mirror +quick|npm +(install|i) ' "$here/entrypoint.sh"; then
  fail "the entrypoint can still install a package at start"
fi

# 4. Runner pods: a toolchain env.sh sets paths and homes, never the runner's
# loader settings (library path, audit, preload, Node options or module path).
declare -F source_runner_toolchains >/dev/null || fail "the entrypoint has no source_runner_toolchains"
mkdir -p "$tmp/tc/media" "$tmp/tc/java"
cat > "$tmp/tc/media/env.sh" <<'ENV'
export PATH="/tc/media/bin:${PATH}"
export LD_LIBRARY_PATH="/tc/media/lib:${LD_LIBRARY_PATH:-}"
export LD_PRELOAD=/tc/media/planted.so
export LD_AUDIT=/tc/media/audit.so
export NODE_OPTIONS="--require /tc/media/planted.js"
export NODE_PATH=/tc/media/node
ENV
printf 'export JAVA_HOME=/tc/java\n' > "$tmp/tc/java/env.sh"
(
  export LD_PRELOAD=/usr/local/lib/eve/eve-nodump.so
  unset LD_LIBRARY_PATH LD_AUDIT NODE_OPTIONS NODE_PATH
  EVE_TOOLCHAIN_PATHS=/tc/media/bin source_runner_toolchains "$tmp/tc"
  env | grep -qx 'LD_PRELOAD=/usr/local/lib/eve/eve-nodump.so' || fail "the runner preload was not kept: ${LD_PRELOAD:-unset}"
  for name in LD_LIBRARY_PATH LD_AUDIT NODE_OPTIONS NODE_PATH; do
    [[ ! -v $name ]] || fail "$name from env.sh reached the runner: ${!name}"
  done
  [[ $JAVA_HOME == /tc/java ]] || fail "JAVA_HOME from env.sh was lost"
  [[ $PATH == /tc/media/bin:* ]] || fail "the toolchain PATH was lost: $PATH"
) || exit 1
(
  # A loader setting the runner already had comes back as it was, and the
  # toolchain PATH comes from EVE_TOOLCHAIN_PATHS even when no env.sh sets it.
  export LD_LIBRARY_PATH=/runner/lib
  EVE_TOOLCHAIN_PATHS=/tc/declared/bin source_runner_toolchains "$tmp/tc"
  [[ $LD_LIBRARY_PATH == /runner/lib ]] || fail "the runner's own LD_LIBRARY_PATH was not restored: $LD_LIBRARY_PATH"
  [[ :$PATH: == *:/tc/declared/bin:* ]] || fail "EVE_TOOLCHAIN_PATHS was not applied: $PATH"
) || exit 1
(
  unset LD_PRELOAD
  export NODE_OPTIONS=--disable-sigusr1
  source_runner_toolchains "$tmp/tc"
  [[ ! -v LD_PRELOAD ]] || fail "a preload from env.sh reached a runner that had none: $LD_PRELOAD"
  [[ $NODE_OPTIONS == --disable-sigusr1 ]] || fail "the runner's own NODE_OPTIONS was not kept: $NODE_OPTIONS"
) || exit 1

echo "PASS: entrypoint installs nothing at start and reports a missing variant; runner loader settings kept"
