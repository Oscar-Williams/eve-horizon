#!/usr/bin/env node
// Supply-chain gate for the platform's build inputs. It fails, listing each
// offence with its file and line, on:
//
//   1. `@latest` anywhere in a Dockerfile; any package without an exact
//      version in a Dockerfile `RUN` that installs or runs one (`npm install`,
//      `npm i`, `npm add`, `npx`, `pnpm add`, `yarn add`, `yarn global add`,
//      `pip install`), or in an `ARG <NAME>_PACKAGE=` default. A version
//      given through a variable (`pkg@${X}`, `pkg==${X}`) must resolve, from
//      an ARG or ENV in scope in that stage, to an exact version;
//   2. a Dockerfile `FROM` (or `COPY --from`) image that is not pinned by an
//      `@sha256:` digest. An earlier stage, `scratch`, and `FROM ${ARG}` whose
//      global ARG default is digest-pinned are allowed;
//   3. a workflow `uses:` not pinned to a full 40-hex commit SHA. Local `./`
//      actions and `docker://` images pinned by digest are allowed;
//   4. a `${{ }}` expression that reads `github.*`, `inputs.*`, `env.*`,
//      `matrix.*`, `steps.*.outputs.*` or `needs.*.outputs.*` inside a
//      workflow `run:` block. Pass the value through `env:` and read the
//      variable instead.
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
// `name==1.2.3` (or `===`), with optional extras and PEP 440 suffixes.
const EXACT_PIP_PACKAGE =
  /^[a-z0-9][\w.-]*(?:\[[\w.,-]+\])?===?\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.post\d+)?(?:\.dev\d+)?$/i;
const COMMIT_PINNED = /^[^@\s]+@[0-9a-f]{40}$/;
const FLOATING_LATEST = /[^\s"'=]*@latest\b/g;
const UNSAFE_IN_RUN = /\b(?:github|inputs|env|matrix)\.|\b(?:steps|needs)\.[\w-]+\.outputs\b/;
const NPM_VALUE_FLAGS = new Set(['--prefix', '--registry', '--cache', '--userconfig', '--omit', '--include']);
const NPX_VALUE_FLAGS = new Set([...NPM_VALUE_FLAGS, '-c', '--call']);
const ADD_VALUE_FLAGS = new Set([...NPM_VALUE_FLAGS, '--filter', '-F', '--dir', '-C', '--cwd', '--store-dir']);
const PIP_VALUE_FLAGS = new Set([
  '-r', '--requirement', '-c', '--constraint', '-e', '--editable', '-i', '--index-url', '--extra-index-url',
  '-f', '--find-links', '-t', '--target', '--prefix', '--root', '--src', '--cache-dir', '--python',
  '--python-version', '--platform', '--implementation', '--abi', '--only-binary', '--no-binary',
  '--trusted-host', '--log', '--proxy', '--timeout', '--retries', '--upgrade-strategy', '-C',
  '--config-settings', '--global-option', '--report', '--progress-bar',
]);

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

/** Expands `$VAR` and `${VAR}` from ARG (or ENV) values; null when one has none. */
function expand(value, args) {
  let unresolved = false;
  const expanded = value.replace(/\$\{(\w+)\}|\$(\w+)/g, (_, braced, bare) => {
    const resolved = args.get(braced ?? bare);
    if (resolved === undefined) {
      unresolved = true;
      return '';
    }
    return resolved;
  });
  return unresolved ? null : expanded;
}

function argDefinitions(rest) {
  return [...rest.matchAll(/(\w+)(?:=("[^"]*"|'[^']*'|\S*))?/g)].map(([, name, value]) => ({
    name,
    value: value === undefined ? undefined : unquote(value),
  }));
}

/** `ENV A=1 B="2"` or the legacy `ENV NAME value`. */
function envDefinitions(rest) {
  const legacy = rest.match(/^(\w+)\s+([^=]*)$/);
  if (legacy) return [{ name: legacy[1], value: unquote(legacy[2].trim()) }];
  return argDefinitions(rest).filter(({ value }) => value !== undefined);
}

const isPackageArg = (token) => token !== '' && !/^[-./~]|^\d*[<>]|:\/\//.test(token);

/** Package arguments after `start`, skipping flags (and the values `valueFlags` take). */
function packageArgsFrom(tokens, start, valueFlags) {
  const specs = [];
  for (let i = start; i < tokens.length; i += 1) {
    const token = unquote(tokens[i]);
    if (/^\d*[<>]/.test(token)) break; // a redirect ends the arguments
    if (valueFlags.has(token)) {
      i += 1;
      continue;
    }
    if (isPackageArg(token)) specs.push(token);
  }
  return specs;
}

/** The package `npx` runs: each `-p`/`--package` value, else its first argument. */
function npxPackages(tokens, start) {
  const packages = [];
  for (let i = start; i < tokens.length; i += 1) {
    const token = unquote(tokens[i]);
    if (/^\d*[<>]/.test(token)) break;
    if (token === '-p' || token === '--package') {
      packages.push(unquote(tokens[i + 1] ?? ''));
      i += 1;
    } else if (token.startsWith('--package=')) {
      packages.push(token.slice('--package='.length));
    } else if (NPX_VALUE_FLAGS.has(token)) {
      i += 1;
    } else if (!token.startsWith('-')) {
      // With -p, this is the command to run; without, the package itself.
      if (packages.length === 0 && isPackageArg(token)) packages.push(token);
      break;
    }
  }
  return packages.filter((token) => token !== '');
}

/**
 * Every package a RUN line installs or runs, as { tool, spec }: `npm
 * install|i|add`, `npx`, `pnpm add`, `yarn [global] add` and `pip install`
 * (`pip3`, `python -m pip`, `uv pip`). Flags and local paths are skipped.
 */
function packageArgs(run) {
  const found = [];
  for (const command of run.split(/&&|\|\||[;|]/)) {
    const tokens = command.trim().split(/\s+/);
    tokens.forEach((token, i) => {
      const next = tokens[i + 1];
      if (token === 'npm' && ['install', 'i', 'add'].includes(next)) {
        for (const spec of packageArgsFrom(tokens, i + 2, NPM_VALUE_FLAGS)) found.push({ tool: 'npm', spec });
      } else if (token === 'npx') {
        for (const spec of npxPackages(tokens, i + 1)) found.push({ tool: 'npx', spec });
      } else if (token === 'pnpm' || token === 'yarn') {
        const add = tokens.indexOf('add', i + 1);
        if (add !== -1) {
          for (const spec of packageArgsFrom(tokens, add + 1, ADD_VALUE_FLAGS)) found.push({ tool: token, spec });
        }
      } else if (token === 'install' && /^pip(?:\d(?:\.\d+)?)?$/.test(tokens[i - 1] ?? '')) {
        for (const spec of packageArgsFrom(tokens, i + 1, PIP_VALUE_FLAGS)) found.push({ tool: 'pip', spec });
      }
    });
  }
  return found;
}

/**
 * Why a package spec is not an exact version, or null when it is. A version
 * given through a variable is read from the ARG and ENV values in scope; a
 * whole spec from a variable is checked only when it resolves (an
 * `ARG <NAME>_PACKAGE=` default is checked where it is declared).
 */
function inexactPackage(tool, spec, vars) {
  if (spec.includes('@latest')) return null; // reported as floating
  const exact = tool === 'pip' ? EXACT_PIP_PACKAGE : EXACT_PACKAGE;
  if (!spec.includes('$')) return exact.test(spec) ? null : `${tool} package ${spec} has no exact version`;
  const resolved = expand(spec, vars);
  if (resolved === null) {
    return spec.startsWith('$') ? null : `${tool} package ${spec} (no default) has no exact version`;
  }
  return exact.test(resolved) ? null : `${tool} package ${spec} (${resolved}) has no exact version`;
}

export function checkDockerfile(text) {
  const offences = new Map();
  const report = (line, message) => offences.set(`${line}:${message}`, { line, message });
  const globalArgs = new Map();
  const stages = new Set();
  const stageEnv = new Map(); // stage name -> its ENV, which a later FROM <stage> inherits
  let vars = new Map(); // ARG and ENV values a RUN in the current stage sees
  let stageName = null;
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
        // In a stage, `ARG NAME` with no value takes the global default.
        if (seenFrom) vars.set(name, value === undefined ? globalArgs.get(name) : expand(value, vars) ?? undefined);
        if (name.endsWith('_PACKAGE') && !(value && EXACT_PACKAGE.test(value)) && !value?.includes('@latest')) {
          report(instruction.line, `ARG ${name}=${value ?? ''} is not an exact package version`);
        }
      }
    } else if (keyword === 'ENV') {
      const env = stageEnv.get(stageName);
      for (const { name, value } of envDefinitions(rest)) {
        const resolved = expand(value, vars) ?? undefined;
        vars.set(name, resolved);
        env?.set(name, resolved);
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
      // A stage sees its parent stage's ENV, never the ARGs before it.
      const parentEnv = resolved === null ? undefined : stageEnv.get(resolved.toLowerCase());
      vars = new Map(parentEnv ?? []);
      stageName = tokens[1]?.toUpperCase() === 'AS' && tokens[2] ? tokens[2].toLowerCase() : null;
      if (stageName) {
        stages.add(stageName);
        stageEnv.set(stageName, new Map(parentEnv ?? []));
      }
    } else if (keyword === 'COPY') {
      const from = rest.match(/--from=(\S+)/)?.[1];
      if (from && !/^\d+$/.test(from) && !stages.has(from.toLowerCase())) {
        const resolved = expand(from, globalArgs);
        if (resolved === null || !(stages.has(resolved.toLowerCase()) || DIGEST_PINNED.test(resolved))) {
          report(instruction.line, `COPY --from=${from} is not pinned by @sha256 digest`);
        }
      }
    } else if (keyword === 'RUN') {
      for (const { tool, spec } of packageArgs(rest)) {
        const problem = inexactPackage(tool, spec, vars);
        if (problem) report(lineOf(instruction, spec), problem);
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
