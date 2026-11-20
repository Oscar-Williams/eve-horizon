#!/usr/bin/env node
// Supply-chain gate for the platform's build inputs. It fails, listing each
// offence with its file and line, on:
//
//   1. `@latest` anywhere in a Dockerfile, and any npm package without an exact
//      version in a Dockerfile `npm install` (`npm i`, `npm add`) or in an
//      `ARG <NAME>_PACKAGE=` default;
//   2. a Dockerfile `FROM` (or `COPY --from`) image that is not pinned by an
//      `@sha256:` digest. An earlier stage, `scratch`, and `FROM ${ARG}` whose
//      global ARG default is digest-pinned are allowed;
//   3. a workflow `uses:` not pinned to a full 40-hex commit SHA. Local `./`
//      actions and `docker://` images pinned by digest are allowed;
//   4. a `${{ }}` expression that reads `github.*`, `inputs.*`,
//      `steps.*.outputs.*` or `needs.*.outputs.*` inside a workflow `run:`
//      block. Pass the value through `env:` and read the variable instead.
//
// Not checked: `tests/manual/**`, which holds throwaway fixtures for manual
// tests rather than anything the platform builds or publishes.
//
// Usage: node scripts/check-supply-chain.mjs [repo-root]

import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const EXEMPT_PREFIXES = ['tests/manual/'];
const SKIPPED_DIRS = new Set(['node_modules', 'dist', 'coverage']);

const DIGEST_PINNED = /@sha256:[0-9a-f]{64}$/;
const EXACT_PACKAGE =
  /^(?:@[a-z0-9][\w.-]*\/)?[a-z0-9][\w.-]*@\d+\.\d+\.\d+(?:-[0-9a-z.-]+)?(?:\+[0-9a-z.-]+)?$/i;
const COMMIT_PINNED = /^[^@\s]+@[0-9a-f]{40}$/;
const FLOATING_LATEST = /[^\s"'=]*@latest\b/g;
const UNSAFE_IN_RUN = /\b(?:github|inputs)\.|\b(?:steps|needs)\.[\w-]+\.outputs\b/;
const NPM_VALUE_FLAGS = new Set(['--prefix', '--registry', '--cache', '--userconfig', '--omit', '--include']);

export function isDockerfile(path) {
  return /(?:^|\/)(?:Dockerfile(?:\.[\w.-]+)?|[\w.-]+\.dockerfile)$/i.test(path);
}

export function isWorkflow(path) {
  return /^\.github\/(?:workflows\/[^/]+|actions\/.+\/action)\.ya?ml$/.test(path);
}

/** Dockerfile instructions with continuation lines joined; each part keeps its line. */
function instructions(text) {
  const result = [];
  let current = null;
  text.split(/\r?\n/).forEach((raw, index) => {
    const line = raw.trimEnd();
    const blank = line.trim() === '' || /^\s*#/.test(line);
    if (blank) return; // comments and blank lines, also inside a continuation
    if (!current) current = { line: index + 1, parts: [] };
    const continued = line.endsWith('\\');
    current.parts.push({ line: index + 1, text: (continued ? line.slice(0, -1) : line).trim() });
    if (!continued) {
      current.text = current.parts.map((part) => part.text).join(' ');
      result.push(current);
      current = null;
    }
  });
  if (current) {
    current.text = current.parts.map((part) => part.text).join(' ');
    result.push(current);
  }
  return result;
}

function unquote(token) {
  return token.replace(/^(['"])(.*)\1$/, '$2');
}

function lineOf(instruction, needle) {
  return instruction.parts.find((part) => part.text.includes(needle))?.line ?? instruction.line;
}

/** Expands `$VAR` and `${VAR}` from ARG defaults; null when one is undefined. */
function expand(value, args) {
  let unresolved = false;
  const expanded = value.replace(/\$\{(\w+)\}|\$(\w+)/g, (_, braced, bare) => {
    const name = braced ?? bare;
    if (!args.has(name)) {
      unresolved = true;
      return '';
    }
    return args.get(name);
  });
  return unresolved ? null : expanded;
}

function argDefinitions(rest) {
  return [...rest.matchAll(/(\w+)(?:=("[^"]*"|'[^']*'|\S*))?/g)].map(([, name, value]) => ({
    name,
    value: value === undefined ? undefined : unquote(value),
  }));
}

/** Package arguments of every `npm install|i|add` command in a RUN line. */
function npmPackageArgs(run) {
  const packages = [];
  for (const command of run.split(/&&|\|\||[;|]/)) {
    const tokens = command.trim().split(/\s+/);
    const npm = tokens.findIndex((token, i) => token === 'npm' && ['install', 'i', 'add'].includes(tokens[i + 1]));
    if (npm === -1) continue;
    for (let i = npm + 2; i < tokens.length; i += 1) {
      const token = unquote(tokens[i]);
      if (NPM_VALUE_FLAGS.has(token)) {
        i += 1;
        continue;
      }
      // Flags, local paths, and variables (their ARG defaults are checked).
      if (token === '' || /^[-./~$]/.test(token) || token.includes('$')) continue;
      packages.push(token);
    }
  }
  return packages;
}

export function checkDockerfile(text) {
  const offences = new Map();
  const report = (line, message) => offences.set(`${line}:${message}`, { line, message });
  const globalArgs = new Map();
  const stages = new Set();
  let seenFrom = false;

  for (const instruction of instructions(text)) {
    const match = instruction.text.match(/^(\w+)\s*(.*)$/s);
    if (!match) continue;
    const keyword = match[1].toUpperCase();
    const rest = match[2];

    for (const [token] of rest.matchAll(FLOATING_LATEST)) {
      report(lineOf(instruction, token), `${token} floats on @latest`);
    }

    if (keyword === 'ARG') {
      for (const { name, value } of argDefinitions(rest)) {
        if (!seenFrom && value !== undefined) globalArgs.set(name, value);
        if (name.endsWith('_PACKAGE') && !(value && EXACT_PACKAGE.test(value)) && !value?.includes('@latest')) {
          report(instruction.line, `ARG ${name}=${value ?? ''} is not an exact package version`);
        }
      }
    } else if (keyword === 'FROM') {
      seenFrom = true;
      const tokens = rest.split(/\s+/).filter((token) => !token.startsWith('--'));
      const image = tokens[0] ?? '';
      const resolved = expand(image, globalArgs);
      const allowed =
        image.toLowerCase() === 'scratch' ||
        (resolved !== null && (stages.has(resolved.toLowerCase()) || DIGEST_PINNED.test(resolved)));
      if (!allowed) {
        const via = resolved === image ? '' : ` (default ${resolved === null ? 'undefined' : resolved})`;
        report(instruction.line, `FROM ${image}${via} is not pinned by @sha256 digest`);
      }
      if (tokens[1]?.toUpperCase() === 'AS' && tokens[2]) stages.add(tokens[2].toLowerCase());
    } else if (keyword === 'COPY') {
      const from = rest.match(/--from=(\S+)/)?.[1];
      if (from && !/^\d+$/.test(from) && !stages.has(from.toLowerCase())) {
        const resolved = expand(from, globalArgs);
        if (resolved === null || !(stages.has(resolved.toLowerCase()) || DIGEST_PINNED.test(resolved))) {
          report(instruction.line, `COPY --from=${from} is not pinned by @sha256 digest`);
        }
      }
    } else if (keyword === 'RUN') {
      for (const spec of npmPackageArgs(rest)) {
        if (EXACT_PACKAGE.test(spec) || spec.includes('@latest')) continue;
        report(lineOf(instruction, spec), `npm package ${spec} has no exact version`);
      }
    }
  }
  return [...offences.values()].sort((a, b) => a.line - b.line);
}

function stripYamlComment(value) {
  return value.replace(/\s+#.*$/, '').trim();
}

export function checkWorkflow(text) {
  const offences = [];
  let run = null; // { indent } while reading a run: value
  const indentOf = (line) => line.match(/^ */)[0].length;
  const checkRun = (fragment, line) => {
    for (const [expression, body] of fragment.matchAll(/\$\{\{(.*?)\}\}/g)) {
      if (UNSAFE_IN_RUN.test(body)) {
        offences.push({ line, message: `run: interpolates ${expression}; pass it through env:` });
      }
    }
  };

  text.split(/\r?\n/).forEach((line, index) => {
    const lineNo = index + 1;
    if (run) {
      if (line.trim() === '' || indentOf(line) > run.indent) {
        checkRun(line, lineNo);
        return;
      }
      run = null;
    }

    const uses = line.match(/^\s*(?:-\s+)?uses:\s*(.*)$/);
    if (uses) {
      const ref = unquote(stripYamlComment(uses[1]));
      const pinned = ref.startsWith('./') || (ref.startsWith('docker://') ? DIGEST_PINNED.test(ref) : COMMIT_PINNED.test(ref));
      if (!pinned) offences.push({ line: lineNo, message: `uses: ${ref} is not pinned to a commit SHA` });
    }

    const runKey = line.match(/^(\s*(?:-\s+)?)run:(.*)$/);
    if (runKey) {
      run = { indent: runKey[1].length };
      checkRun(runKey[2], lineNo);
    }
  });
  return offences;
}

function* walk(root, dir = root) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    const rel = relative(root, path).split(sep).join('/');
    if (EXEMPT_PREFIXES.some((prefix) => `${rel}/`.startsWith(prefix))) continue;
    if (entry.isDirectory()) {
      if (SKIPPED_DIRS.has(entry.name) || (entry.name.startsWith('.') && entry.name !== '.github')) continue;
      yield* walk(root, path);
    } else if (entry.isFile()) {
      yield rel;
    }
  }
}

/** Every offence under `root`, as { file, line, message }, with a count of files checked. */
export function scan(root) {
  const offences = [];
  const checked = { dockerfiles: 0, workflows: 0 };
  for (const file of walk(root)) {
    const check = isDockerfile(file) ? checkDockerfile : isWorkflow(file) ? checkWorkflow : null;
    if (!check) continue;
    checked[check === checkDockerfile ? 'dockerfiles' : 'workflows'] += 1;
    for (const offence of check(readFileSync(join(root, file), 'utf8'))) offences.push({ file, ...offence });
  }
  offences.sort((a, b) => a.file.localeCompare(b.file) || a.line - b.line);
  return { offences, checked };
}

export function findOffences(root) {
  return scan(root).offences;
}

export function formatOffence({ file, line, message }) {
  return `${file}:${line}: ${message}`;
}

function main() {
  const root = resolve(process.argv[2] ?? join(dirname(fileURLToPath(import.meta.url)), '..'));
  const { offences, checked } = scan(root);
  const files = `${checked.dockerfiles} Dockerfiles and ${checked.workflows} workflows`;
  if (offences.length === 0) {
    console.log(`supply chain: no offences in ${files}`);
    return;
  }
  for (const offence of offences) console.error(formatOffence(offence));
  console.error(`supply chain: ${offences.length} offences in ${files}`);
  process.exitCode = 1;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main();
