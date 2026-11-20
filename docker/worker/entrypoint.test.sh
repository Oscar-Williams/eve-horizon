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

echo "PASS: entrypoint installs nothing at start and reports a missing variant"
