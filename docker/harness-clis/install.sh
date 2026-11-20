#!/bin/sh
# Installs the harness CLIs locked in this directory into /opt/harness-clis and
# links their commands into /usr/local/bin. The worker and agent-runtime
# Dockerfiles run it as root; the prefix stays root-owned, so the CLIs need no
# root at runtime and job code cannot change them.
#
# Versions change only here: edit package.json, then regenerate the lock with
# npm 11 or later (it records each platform package's libc):
#   npm install --package-lock-only --ignore-scripts
#
# An INSTALL_<NAME>=false build arg (worker) leaves that CLI out of the image.
set -eu

prefix=/opt/harness-clis
modules="$prefix/node_modules"
cd "$prefix"

# Exact versions, checked against the lock's integrity hashes, with every
# lifecycle script off. The two CLIs that need an install step get it below.
# A throwaway cache keeps the downloaded tarballs out of the image.
cache=$(mktemp -d)
npm ci --ignore-scripts --omit=dev --no-audit --no-fund --no-update-notifier --cache "$cache"
rm -rf "$cache"

# npm 10 (bundled with node 22) ignores the libc recorded in the lock and
# installs both the glibc and the musl build of a native package. Keep this
# system's only, in the same layer.
node -e '
  const { rmSync } = require("node:fs");
  const libc = process.report.getReport().header.glibcVersionRuntime ? "glibc" : "musl";
  for (const [path, entry] of Object.entries(require(process.argv[1]).packages)) {
    if (entry.libc && !entry.libc.includes(libc)) rmSync(path, { recursive: true, force: true });
  }' "$prefix/package-lock.json"

arch=$(node -p process.arch)

while read -r package commands switch; do
  commands=$(echo "$commands" | tr , ' ')
  eval "enabled=\${$switch:-true}"
  if [ "$enabled" != true ]; then
    # The package and its platform builds (<package>-linux-<arch>...).
    rm -rf "$modules/$package" "$modules/$package"-*
    for command in $commands; do rm -f "$modules/.bin/$command"; done
    continue
  fi

  case "$package" in
    @anthropic-ai/claude-code)
      # bin/claude.exe is a stub until the package's postinstall copies the
      # native binary over it from the platform package the lock installed
      # (@anthropic-ai/claude-code-linux-<arch>). It reads only local files.
      node "$modules/$package/install.cjs"
      ;;
    @just-every/code)
      # coder.js runs bin/code-<triple>. The package's postinstall copies it
      # there from the platform package, and downloads it from GitHub when
      # that package is missing (coder.js does the same at first run). Link
      # it from the locked platform package instead, so nothing is fetched.
      triple=$([ "$arch" = x64 ] && echo x86_64 || echo aarch64)-unknown-linux-musl
      ln -f "$modules/$package-linux-$arch-musl/bin/code-$triple" "$modules/$package/bin/code-$triple"
      chmod 0755 "$modules/$package/bin/code-$triple"
      ;;
  esac

  for command in $commands; do
    [ -x "$modules/.bin/$command" ] || { echo "harness-clis: $package has no $command command" >&2; exit 1; }
    ln -sf "$modules/.bin/$command" "/usr/local/bin/$command"
  done
done <<'EOF'
@anthropic-ai/claude-code claude INSTALL_CLAUDE
@openai/codex codex INSTALL_CODEX
@google/gemini-cli gemini INSTALL_GEMINI
@just-every/code coder INSTALL_CODE
@mariozechner/pi-coding-agent pi INSTALL_PI
cc-mirror cc-mirror INSTALL_MIRROR
skills skills,add-skill INSTALL_SKILLS
EOF
