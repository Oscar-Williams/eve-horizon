/**
 * Harness settings a checkout supplies (rule harness.checkout_settings, P2-9).
 *
 * A harness reads settings from the job's checkout as well as from Eve:
 * Claude Code from `.claude/settings.json` and `settings.local.json`, Codex
 * from a trusted project's `.codex/config.toml` (and from its config home,
 * `config.toml` and the `.env` Codex loads over its own environment, when
 * that is the checkout's `.agent/harnesses/codex/`), Gemini from the `.env`
 * files it finds, and every Claude-family harness from Eve's copy of
 * `.agent/harnesses/<harness>/`. A setting there can send model traffic,
 * with the job's provider key, somewhere the job's own routing does not:
 * a base URL, a proxy, a TLS trust store, code loaded before the harness
 * starts, or a key helper.
 *
 * An MCP server the checkout defines can also be handed a credential by
 * name and send it where the checkout chooses: Codex's `env_vars`,
 * `bearer_token_env_var` and `env_http_headers`, and the `$NAME` or
 * `${NAME}` references Claude Code (`.mcp.json`, the config directory's
 * `.claude.json`) and Gemini (`.gemini/settings.json`) expand. A server that
 * names a credential of the running harness or of Eve
 * (`isCheckoutCredentialEnvKey`) or a routing name is a finding, as is a
 * Codex server whose `auth` is not `oauth`.
 *
 * Under `audit` the run records what it finds (names, never values). Under
 * `strict` the harness proxy keeps those settings away from the harness,
 * without editing a checkout file (an agent may commit them):
 *
 * - **Claude Code** (and the cc-mirror wrappers, which pass flags through)
 *   gets a cleaned copy of the project and local settings through
 *   `--settings`, with `--setting-sources user`, so the originals are not
 *   read; Eve's copy of the config directory is cleaned in place.
 * - **Codex** is refused when a checkout config (the project's
 *   `.codex/config.toml`, or a config home inside the checkout, the default
 *   `CODEX_HOME`) sets any routing setting, widens what shell commands
 *   inherit or hands an MCP server a credential, or when that config home
 *   has a `.env` at all (Codex expands `${NAME}` in it), since the file
 *   cannot be edited and `-c` cannot undo a profile the file chooses.
 *   Otherwise it gets `-c model_provider="openai"` (and the same for the
 *   variant profile).
 * - **Gemini** gets a per-job, Eve-owned system settings file, which outranks
 *   workspace settings, excluding the routing names from the project `.env`;
 *   routing names in `.gemini/.env`, which Gemini loads whatever the
 *   exclusions, are refused.
 * - A checkout MCP server that names a credential or routing variable is
 *   refused for every harness.
 * - A settings file the scan cannot parse (JSON; Gemini's JSON with
 *   comments; TOML) is `(unreadable)`, and refused.
 * - A harness with no confirmed mechanism is refused.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { CLAUDE_AUTH_ENV_KEYS } from '../invoke/claude-auth.js';
import { isUserSecretWithheldKey } from '../schemas/job.js';
import type { SecurityProfile } from '../security/profile.js';
import { isHarnessCredentialKey } from './auth.js';
import { parseToml, type TomlTable, type TomlValue } from './toml.js';

/** The rule's id (rule set 2). */
export const CHECKOUT_SETTINGS_RULE = 'harness.checkout_settings';

/**
 * Set to `strict` in the harness proxy's environment when the project's
 * profile enforces the rule. The name is Eve's (EVE_ is reserved), so no env
 * override can set it.
 */
export const CHECKOUT_SETTINGS_ENV = 'EVE_HARNESS_CHECKOUT_SETTINGS';

export type CheckoutSettingsMechanism = 'claude' | 'codex' | 'gemini';

/**
 * How a harness is kept from checkout routing settings, checked against the
 * pinned harness versions; null when there is no confirmed way (refused
 * under `strict`).
 */
export function checkoutSettingsMechanism(harness: string): CheckoutSettingsMechanism | null {
  switch (harness) {
    case 'claude':
    case 'mclaude':
    case 'zai':
      return 'claude';
    case 'codex':
      return 'codex';
    case 'gemini':
      return 'gemini';
    default:
      return null;
  }
}

/**
 * Env names a checkout may not set for the harness: P1-9's routing names
 * (base URLs, proxies, TLS trust), NODE_OPTIONS and the code-loading names.
 */
export function isCheckoutRoutingEnvKey(key: string): boolean {
  return isUserSecretWithheldKey(key);
}

/**
 * Env names that hold a credential a checkout MCP server may not be handed
 * when this harness runs: the harness's own provider keys and auth names
 * (`isHarnessCredentialKey`; Claude Code's auth names for the Claude family,
 * Codex's `CODEX_` names for Codex) and Eve's secret-bearing names
 * (`isEveSecretEnvKey`). Any other name, another harness's key or Eve's
 * plain settings such as `EVE_API_URL` among them, is the project's own.
 */
export function isCheckoutCredentialEnvKey(key: string, harness: string): boolean {
  const name = key.toUpperCase();
  if (isEveSecretEnvKey(name) || isHarnessCredentialKey(harness, name)) return true;
  switch (checkoutSettingsMechanism(harness) ?? harness) {
    case 'claude':
      return (CLAUDE_AUTH_ENV_KEYS as readonly string[]).includes(name);
    case 'codex':
    case 'code':
      return name.startsWith('CODEX_');
    default:
      return false;
  }
}

/** Words that mark an `EVE_` name as carrying a secret. */
const EVE_SECRET_WORDS = new Set(['TOKEN', 'KEY', 'SECRET', 'SECRETS', 'PASSWORD', 'CREDENTIAL', 'CREDENTIALS', 'AUTHKEY']);

/**
 * Eve's names that carry a secret: an `EVE_` name with a token, key, secret,
 * password or credential word, such as `EVE_JOB_TOKEN`, the
 * `EVE_APP_LINK_<APP>_TOKEN` link tokens and the internal keys
 * (`EVE_INTERNAL_API_KEY`, `EVE_INTERNAL_CORE_KEY` and the rest). Plain
 * settings (`EVE_API_URL`, `EVE_PROJECT_ID`, `EVE_JOB_ID`) are not.
 */
export function isEveSecretEnvKey(key: string): boolean {
  const name = key.toUpperCase();
  return name.startsWith('EVE_') && name.split('_').some((word) => EVE_SECRET_WORDS.has(word));
}

/** One checkout file and the routing settings it sets (names only). */
export interface CheckoutRoutingFinding {
  file: string;
  settings: string[];
}

/** The message a refusal under `strict` carries. */
export function checkoutSettingsRefusal(reason: string): string {
  return `${reason} (rule ${CHECKOUT_SETTINGS_RULE})`;
}

/**
 * The routing settings the checkout supplies to this harness, file by file,
 * in the order the harness reads them. `configDir` is the harness config
 * directory the run uses (Eve's copy of `.agent/harnesses/<harness>/`, or
 * that directory itself).
 */
export function findCheckoutRouting(params: { workspace: string; harness: string; configDir?: string }): CheckoutRoutingFinding[] {
  const { workspace, harness, configDir } = params;
  const found: CheckoutRoutingFinding[] = [];
  const add = (file: string, settings: string[]) => {
    if (settings.length > 0) found.push({ file, settings });
  };
  switch (checkoutSettingsMechanism(harness) ?? harness) {
    case 'claude': {
      for (const name of CLAUDE_CHECKOUT_FILES) {
        add(name, claudeRoutingSettings(readJson(path.join(workspace, name))));
      }
      if (configDir) {
        add(configLabel(workspace, harness, configDir, 'settings.json'), claudeRoutingSettings(readJson(path.join(configDir, 'settings.json'))));
      }
      found.push(...checkoutMcpFindings(workspace, harness, configDir));
      break;
    }
    case 'codex':
    case 'code': {
      add('.codex/config.toml', codexRoutingSettings(readText(path.join(workspace, '.codex', 'config.toml')), harness));
      // A config home inside the checkout is the checkout's; Eve's own is not.
      if (configDir && isInside(workspace, configDir)) {
        add(configLabel(workspace, harness, configDir, 'config.toml'), codexRoutingSettings(readText(path.join(configDir, 'config.toml')), harness));
        // Codex loads CODEX_HOME/.env over its own environment (keeping out
        // only CODEX_ names) and expands ${NAME} in its values, so a harmless
        // name can carry a credential: the file is a finding whatever it holds.
        add(configLabel(workspace, harness, configDir, '.env'), envFileNames(readText(path.join(configDir, '.env'))));
      }
      break;
    }
    case 'gemini': {
      for (const name of GEMINI_ENV_FILES) {
        add(name, envFileRoutingNames(readText(path.join(workspace, name))));
      }
      found.push(...checkoutMcpFindings(workspace, harness));
      break;
    }
    default:
      break;
  }
  return found;
}

/** A copy of Claude Code settings without routing env names and the key helper. */
export function cleanClaudeSettings(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) return {};
  const { apiKeyHelper: _helper, ...rest } = value;
  if (!isRecord(rest.env)) return rest;
  return {
    ...rest,
    env: Object.fromEntries(Object.entries(rest.env).filter(([key]) => !isCheckoutRoutingEnvKey(key))),
  };
}

/**
 * Claude Code under `strict`: write a cleaned merge of the checkout's project
 * and local settings to a file of Eve's, and clean Eve's copy of the config
 * directory. Returns the flags that make Claude Code read only those and its
 * user settings. A config directory inside the checkout that sets routing is
 * refused: it would have to be edited. So is an MCP server, in `.mcp.json`
 * or the config directory's `.claude.json`, that names a credential or
 * routing variable, and any of these files that cannot be parsed.
 */
export function strictClaudeSettingsArgs(workspace: string, configDir: string | undefined, harness = 'claude'): string[] {
  refuseFindings(checkoutMcpFindings(workspace, harness, configDir));
  const [project, local] = CLAUDE_CHECKOUT_FILES.map((name) => readJson(path.join(workspace, name)));
  const userSettingsPath = configDir ? path.join(configDir, 'settings.json') : undefined;
  const user = userSettingsPath ? readJson(userSettingsPath) : null;
  refuseFindings([
    { file: CLAUDE_CHECKOUT_FILES[0], value: project },
    { file: CLAUDE_CHECKOUT_FILES[1], value: local },
    ...(configDir ? [{ file: configLabel(workspace, harness, configDir, 'settings.json'), value: user }] : []),
  ].filter(({ value }) => value === UNPARSED).map(({ file }) => ({ file, settings: [UNREADABLE] })));
  if (configDir && userSettingsPath && claudeRoutingSettings(user).length > 0) {
    if (isInside(workspace, configDir)) {
      throw new Error(checkoutSettingsRefusal(
        `The harness config directory ${path.relative(workspace, configDir)} in the checkout sets routing settings`,
      ));
    }
    fs.writeFileSync(userSettingsPath, JSON.stringify(cleanClaudeSettings(user), null, 2));
  }
  const merged = mergeSettings(project, local);
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eve-claude-settings-')), 'settings.json');
  fs.writeFileSync(file, JSON.stringify(cleanClaudeSettings(merged), null, 2), { mode: 0o600 });
  return ['--settings', file, '--setting-sources', 'user'];
}

/**
 * Codex under `strict`: a checkout config that sets any routing setting is
 * refused. It cannot be edited (an agent may commit it), and `-c` cannot
 * reliably undo it: a `profile` the file chooses outranks the top-level
 * keys `-c` sets. Otherwise `-c` overrides (the top config layer) pin the
 * built-in OpenAI provider, which honours the job's own OPENAI_BASE_URL, for
 * the base config and the variant's profile.
 */
export function strictCodexArgs(workspace: string, codexHome: string | undefined, variant: string | undefined): string[] {
  const routed = findCheckoutRouting({ workspace, harness: 'codex', configDir: codexHome })
    .flatMap((finding) => finding.settings.map((setting) => `${finding.file}: ${setting}`));
  if (routed.length > 0) {
    throw new Error(checkoutSettingsRefusal(`The checkout's Codex config is refused: ${routed.join(', ')}`));
  }
  const args = ['-c', 'model_provider="openai"'];
  if (variant) args.push('-c', `profiles.${variant}.model_provider="openai"`);
  return args;
}

/**
 * Gemini under `strict`: the settings to put in Eve's system settings file
 * (which outranks workspace settings) so the project `.env` cannot set a
 * routing name. Routing names in `.gemini/.env`, which Gemini loads whatever
 * the exclusions, are refused, as is workspace settings that reference a
 * credential or routing variable anywhere (an MCP server, a telemetry
 * endpoint) or cannot be parsed.
 */
export function strictGeminiSystemSettings(workspace: string): { advanced: { excludedEnvVars: string[] } } {
  refuseFindings(checkoutMcpFindings(workspace, 'gemini'));
  const pinned = envFileRoutingNames(readText(path.join(workspace, '.gemini', '.env')));
  if (pinned.length > 0) {
    throw new Error(checkoutSettingsRefusal(`The checkout's .gemini/.env sets ${pinned.join(', ')}`));
  }
  // Setting the list replaces Gemini's default, so it is kept.
  return { advanced: { excludedEnvVars: [...GEMINI_DEFAULT_EXCLUDED_ENV_VARS, ...envFileRoutingNames(readText(path.join(workspace, '.env')))] } };
}

/**
 * Hold a run to the rule. Reads the project's profile; under `audit` and
 * `strict` records what the checkout supplies (names only); under `strict`
 * returns the environment that tells the harness proxy to keep it out, and
 * refuses a harness with no confirmed mechanism.
 */
export async function holdCheckoutSettings(params: {
  harness: string;
  workspace: string;
  configDir?: string;
  /** The project's profile for the rule, read without recording. */
  profile: () => Promise<SecurityProfile>;
  /** Decide the rule with this detail, recording a finding. */
  record: (detail: Record<string, string>) => Promise<unknown>;
}): Promise<Record<string, string>> {
  const profile = await params.profile();
  if (profile === 'legacy') return {};
  const findings = findCheckoutRouting(params);
  if (findings.length > 0) {
    await params.record({
      harness: params.harness,
      files: findings.map((finding) => finding.file).join(','),
      settings: [...new Set(findings.flatMap((finding) => finding.settings))].join(','),
    });
  }
  if (profile !== 'strict') return {};
  if (!checkoutSettingsMechanism(params.harness)) {
    throw new Error(checkoutSettingsRefusal(
      `Harness ${params.harness} has no confirmed way to keep checkout settings from rerouting it; use claude, codex or gemini`,
    ));
  }
  return { [CHECKOUT_SETTINGS_ENV]: 'strict' };
}

// ── Reading settings ────────────────────────────────────────────────────

const CLAUDE_CHECKOUT_FILES = ['.claude/settings.json', '.claude/settings.local.json'];
const GEMINI_ENV_FILES = ['.gemini/.env', '.env'];
/** Gemini CLI's own default for `advanced.excludedEnvVars`. */
const GEMINI_DEFAULT_EXCLUDED_ENV_VARS = ['DEBUG', 'DEBUG_MODE'];

function claudeRoutingSettings(value: unknown): string[] {
  if (value === UNPARSED) return [UNREADABLE];
  if (!isRecord(value)) return [];
  const settings: string[] = [];
  if ('apiKeyHelper' in value) settings.push('apiKeyHelper');
  if (isRecord(value.env)) {
    for (const key of Object.keys(value.env)) {
      if (isCheckoutRoutingEnvKey(key)) settings.push(`env.${key}`);
    }
  }
  return settings.sort();
}

/**
 * Codex config keys that choose the provider or where it sends traffic, by
 * dotted name, read with a TOML parser so every form counts (tables, dotted
 * keys, inline tables, quoted keys): the top-level `profile` (it selects a
 * profile's provider), `model_provider` at any depth (profiles included),
 * each `model_providers` entry, any key ending `base_url`, and any env
 * override (an upper-case key with a value, such as
 * `shell_environment_policy.set.OPENAI_BASE_URL` or an MCP server's `env`)
 * that sets a routing name, a `shell_environment_policy` that widens what
 * shell commands inherit (`codexShellWidening`); then the MCP servers it
 * hands a credential (`codexMcpHandoffs`). A file it cannot read is
 * `(unreadable)`.
 */
function codexRoutingSettings(text: string | null, harness: string): string[] {
  if (!text) return [];
  let doc: TomlTable;
  try {
    doc = parseToml(text);
  } catch {
    return [UNREADABLE];
  }
  const settings = new Set<string>();
  const walk = (table: TomlTable, keys: string[]) => {
    for (const [key, value] of Object.entries(table)) {
      const path = [...keys, key];
      const name = path.join('.');
      if (path.length === 1 && key === 'model_providers') {
        const entries = isTable(value) ? Object.keys(value) : [];
        for (const entry of entries.length > 0 ? entries : ['']) settings.add(entry ? `${name}.${entry}` : name);
        continue;
      }
      if (key === 'shell_environment_policy' && isTable(value)) {
        for (const setting of codexShellWidening(value, harness)) settings.add(`${name}.${setting}`);
      }
      if ((path.length === 1 && key === 'profile') || key === 'model_provider' || /base_url$/i.test(key)) {
        settings.add(name);
      } else if (!isTable(value) && !Array.isArray(value) && /^[A-Z_][A-Z0-9_]*$/.test(key) && isCheckoutRoutingEnvKey(key)) {
        settings.add(name);
      }
      for (const child of Array.isArray(value) ? value : [value]) {
        if (isTable(child)) walk(child, path);
      }
    }
  };
  walk(doc, []);
  return [...settings, ...codexMcpHandoffs(doc, harness)];
}

/**
 * Codex MCP servers that take a credential or routing variable from Codex's
 * environment by name: a stdio server's `env_vars` (a stdio server otherwise
 * gets only a few basic names), an HTTP server's `bearer_token_env_var` and
 * `env_http_headers` values (sent to the server's URL; header names are any
 * case, so only the values count), and an `auth` other than `oauth` (the
 * ChatGPT session, which Codex itself keeps to ChatGPT's origin, or an IdP
 * token exchange). `http_headers_helper` runs with only the basic names.
 */
function codexMcpHandoffs(doc: TomlTable, harness: string): string[] {
  const servers = doc.mcp_servers;
  if (!isTable(servers)) return [];
  const found: string[] = [];
  const named = (envName: TomlValue | undefined, at: string) => {
    if (typeof envName === 'string' && namesHarnessSecret(envName, harness)) found.push(`${at}=$${envName}`);
  };
  for (const [name, server] of Object.entries(servers)) {
    if (!isTable(server)) continue;
    const at = `mcp_servers.${name}`;
    for (const [field, value] of Object.entries(server)) {
      if (field === 'bearer_token_env_var') {
        named(value, `${at}.${field}`);
      } else if (field === 'env_http_headers' && isTable(value)) {
        for (const [header, envName] of Object.entries(value)) named(envName, `${at}.${field}.${header}`);
      } else if (field === 'env_vars' && Array.isArray(value)) {
        value.forEach((entry, i) => (isTable(entry) ? named(entry.name, `${at}.${field}.${i}.name`) : named(entry, `${at}.${field}.${i}`)));
      } else if (field === 'auth' && value !== 'oauth') {
        found.push(`${at}.auth`);
      }
    }
  }
  return found;
}

/**
 * `shell_environment_policy` keys that widen what Codex's shell commands
 * inherit: `inherit = "all"`, `ignore_default_excludes = true`, an
 * `include_only` pattern or `filters` include that keeps a credential, and a
 * `set` entry that names or references one.
 */
function codexShellWidening(policy: TomlTable, harness: string): string[] {
  const found: string[] = [];
  if (policy.inherit === 'all') found.push('inherit=all');
  if (policy.ignore_default_excludes === true) found.push('ignore_default_excludes');
  const includes = Array.isArray(policy.include_only) ? policy.include_only : [];
  if (includes.some((pattern) => typeof pattern === 'string' && keepsCredential(pattern, harness))) found.push('include_only');
  const filters = isTable(policy.filters) ? Object.entries(policy.filters) : [];
  if (filters.some(([pattern, filter]) => filter === 'include' && keepsCredential(pattern, harness))) found.push('filters');
  for (const [key, value] of Object.entries(isTable(policy.set) ? policy.set : {})) {
    if (isCheckoutCredentialEnvKey(key, harness)) found.push(`set.${key}`);
    for (const [, name] of typeof value === 'string' ? value.matchAll(ENV_REFERENCE) : []) {
      if (namesHarnessSecret(name, harness)) found.push(`set.${key}=$${name}`);
    }
  }
  return found;
}

/** Credential names a wildcard include pattern is tried against. */
const CREDENTIAL_PROBES = [
  ...CLAUDE_AUTH_ENV_KEYS, 'OPENAI_API_KEY', 'CODEX_API_KEY', 'CODEX_AUTH_JSON', 'CODEX_AUTH_JSON_B64', 'CODEX_OAUTH_ACCESS_TOKEN',
  'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'Z_AI_API_KEY', 'ZAI_API_KEY', 'EVE_JOB_TOKEN', 'EVE_APP_LINK_APP_TOKEN', 'EVE_INTERNAL_API_KEY',
];

/** Whether a Codex env pattern (`*` and `?` wildcards, any case) keeps a credential of this run. */
function keepsCredential(pattern: string, harness: string): boolean {
  if (!/[*?]/.test(pattern)) return isCheckoutCredentialEnvKey(pattern, harness);
  const glob = new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.')}$`, 'i');
  return CREDENTIAL_PROBES.some((name) => glob.test(name) && isCheckoutCredentialEnvKey(name, harness));
}

/** Whether a checkout MCP server may not be handed this env name: a credential or a routing name. */
function namesHarnessSecret(name: string, harness: string): boolean {
  return isCheckoutCredentialEnvKey(name, harness) || isCheckoutRoutingEnvKey(name);
}

/** `$NAME` and `${NAME}` (with or without `:-default`) references in a string. */
const ENV_REFERENCE = /\$\{?([A-Za-z_][A-Za-z0-9_]*)/g;

/**
 * The credential handoffs in JSON settings a checkout supplies to Claude Code
 * or Gemini, file by file: the MCP servers in Claude Code's project
 * `.mcp.json` and the config directory's `.claude.json` (user and
 * per-project servers), and every string in Gemini's workspace
 * `.gemini/settings.json`. Each string (a server's command, args, env, url,
 * headers, headersHelper; for Gemini also a telemetry endpoint or tool
 * command) that references a credential or routing name, as `$NAME` or
 * `${NAME}`, is named. Both harnesses expand those references, and a header
 * helper runs in a shell that can.
 */
function checkoutMcpFindings(workspace: string, harness: string, configDir?: string): CheckoutRoutingFinding[] {
  const files: Array<[string, string[]]> = checkoutSettingsMechanism(harness) === 'gemini'
    // Gemini expands references in every settings string (telemetry endpoints, tool commands), so all count.
    ? [['.gemini/settings.json', jsonHandoffs(readJson(path.join(workspace, '.gemini', 'settings.json'), parseJsonWithComments), harness, 'all')]]
    : [
      ['.mcp.json', jsonHandoffs(readJson(path.join(workspace, '.mcp.json')), harness, 'servers')],
      ...(configDir
        ? [[configLabel(workspace, harness, configDir, '.claude.json'), jsonHandoffs(readJson(path.join(configDir, '.claude.json')), harness, 'servers')] as [string, string[]]]
        : []),
    ];
  return files
    .map(([file, settings]) => ({ file, settings }))
    .filter((finding) => finding.settings.length > 0);
}

/**
 * The `$NAME` and `${NAME}` references to a credential or routing name in a
 * JSON settings file: in its MCP servers (`mcpServers` and each
 * `projects.<path>.mcpServers`), or in every string it holds.
 */
function jsonHandoffs(value: unknown, harness: string, scope: 'servers' | 'all'): string[] {
  if (value === UNPARSED) return [UNREADABLE];
  if (!isRecord(value)) return [];
  const found: string[] = [];
  const scan = (item: unknown, at: string) => {
    const under = (key: string | number) => (at ? `${at}.${key}` : String(key));
    if (typeof item === 'string') {
      for (const [, name] of item.matchAll(ENV_REFERENCE)) {
        if (namesHarnessSecret(name, harness)) found.push(`${at}=$${name}`);
      }
    } else if (Array.isArray(item)) {
      item.forEach((entry, i) => scan(entry, under(i)));
    } else if (isRecord(item)) {
      for (const [key, entry] of Object.entries(item)) scan(entry, under(key));
    }
  };
  if (scope === 'all') {
    scan(value, '');
  } else {
    scan(value.mcpServers, 'mcpServers');
    if (isRecord(value.projects)) {
      for (const [project, entry] of Object.entries(value.projects)) {
        if (isRecord(entry)) scan(entry.mcpServers, `projects.${project}.mcpServers`);
      }
    }
  }
  return [...new Set(found)];
}

function refuseFindings(findings: CheckoutRoutingFinding[]): void {
  if (findings.length === 0) return;
  const named = findings.flatMap((finding) => finding.settings.map((setting) => `${finding.file}: ${setting}`));
  throw new Error(checkoutSettingsRefusal(`Checkout settings hand over a credential or routing variable, or cannot be read: ${named.join(', ')}`));
}

function isTable(value: TomlValue | undefined): value is TomlTable {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** The variables an env file sets, by name, sorted. */
function envFileVariables(text: string): string[] {
  const names = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (match) names.add(match[1]);
  }
  return [...names].sort();
}

function envFileRoutingNames(text: string | null): string[] {
  return text ? envFileVariables(text).filter(isCheckoutRoutingEnvKey) : [];
}

/** Every variable an env file that exists sets; `(no variables)` when it sets none. */
function envFileNames(text: string | null): string[] {
  if (text === null) return [];
  const names = envFileVariables(text);
  return names.length > 0 ? names : ['(no variables)'];
}

/** Claude Code's merge of settings sources: objects merge, lists join, the later scalar wins. */
function mergeSettings(base: unknown, over: unknown): Record<string, unknown> {
  const left = isRecord(base) ? base : {};
  const right = isRecord(over) ? over : {};
  const merged: Record<string, unknown> = { ...left };
  for (const [key, value] of Object.entries(right)) {
    const prior = merged[key];
    if (Array.isArray(prior) && Array.isArray(value)) merged[key] = [...new Set([...prior, ...value])];
    else if (isRecord(prior) && isRecord(value)) merged[key] = mergeSettings(prior, value);
    else merged[key] = value;
  }
  return merged;
}

function configLabel(workspace: string, harness: string, configDir: string, file: string): string {
  return isInside(workspace, configDir)
    ? path.join(path.relative(workspace, configDir), file)
    : path.join('.agent', 'harnesses', harness, file);
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(path.resolve(root), path.resolve(candidate));
  return relative === '' || (!relative.startsWith('..') && !path.isAbsolute(relative));
}

function readText(file: string): string | null {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

/** The setting a file that exists but cannot be parsed stands for. */
const UNREADABLE = '(unreadable)';
/** What `readJson` returns for a file that exists but cannot be parsed. */
const UNPARSED = Symbol('unparsed');

/** A JSON file's value: null when it does not exist, `UNPARSED` when it cannot be parsed. */
function readJson(file: string, parse: (text: string) => unknown = JSON.parse): unknown {
  const text = readText(file);
  if (text === null) return null;
  try {
    return parse(text);
  } catch {
    return UNPARSED;
  }
}

/** JSON with `//` and block comments outside strings, which Gemini CLI strips before parsing its settings. */
function parseJsonWithComments(text: string): unknown {
  return JSON.parse(text.replace(/("(?:\\.|[^"\\])*")|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (_comment, string?: string) => string ?? ' '));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
