#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=scripts/release/common.sh
source "$(dirname "$0")/common.sh"
# A release tag publishes only history that has reached origin/main or an
# origin/hotfix/* branch (cut from the release tag it fixes). Needs a full
# clone: in a shallow one the check fails closed.
[[ $# -eq 1 ]] || release_die 'usage: ancestry.sh <commit>'
commit=$(git rev-parse --verify --quiet "$1^{commit}") || release_die "unknown commit: $1"
while IFS= read -r branch; do
  if git merge-base --is-ancestor "$commit" "$branch"; then
    echo "release commit $commit is on ${branch#refs/remotes/}"
    exit 0
  fi
done < <(git for-each-ref --format='%(refname)' refs/remotes/origin/main 'refs/remotes/origin/hotfix/*')
release_die "commit $commit is on neither origin/main nor an origin/hotfix/* branch"
