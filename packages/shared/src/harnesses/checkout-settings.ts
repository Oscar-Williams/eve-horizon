/**
 * Harness settings a checkout supplies (rule harness.checkout_settings, P2-9).
 *
 * A harness reads settings from the job's checkout as well as from Eve:
 * Claude Code from `.claude/settings.json` and `settings.local.json`, Codex
 * from a trusted project's `.codex/config.toml` (and from its config home
 * when that is the checkout's `.agent/harnesses/codex/`), Gemini from the
 * `.env` files it finds, and every Claude-family harness from Eve's copy of
 * `.agent/harnesses/<harness>/`. A setting there can send model traffic,
 * with the job's provider key, somewhere the job's own routing does not:
 * a base URL, a proxy, a TLS trust store, code loaded before the harness
 * starts, or a key helper.
 *
 * Under `audit` the run records what it finds (names, never values). Under
 * `strict` the harness proxy keeps those settings away from the harness,
 * without editing a checkout file (an agent may commit them):
 *
 * - **Claude Code** (and the cc-mirror wrappers, which pass flags through)
 *   gets a cleaned copy of the project and local settings through
 *   `--settings`, with `--setting-sources user`, so the originals are not
 *   read; Eve's copy of the config directory is cleaned in place.
 * - **Codex** gets `-c model_provider="openai"` (and the same for the variant
 *   profile), which outranks the project and user config layers; a base URL
 *   no override can undo is refused.
 * - **Gemini** gets a per-job, Eve-owned system settings file, which outranks
 *   workspace settings, excluding the routing names from the project `.env`;
 *   routing names in `.gemini/.env`, which Gemini loads whatever the
 *   exclusions, are refused.
 * - A harness with no confirmed mechanism is refused.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { isUserSecretWithheldKey } from '../schemas/job.js';
import type { SecurityProfile } from '../security/profile.js';

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
      break;
    }
    case 'codex':
    case 'code': {
      add('.codex/config.toml', codexRoutingSettings(readText(path.join(workspace, '.codex', 'config.toml'))));
      // A config home inside the checkout is the checkout's; Eve's own is not.
      if (configDir && isInside(workspace, configDir)) {
        add(configLabel(workspace, harness, configDir, 'config.toml'), codexRoutingSettings(readText(path.join(configDir, 'config.toml'))));
      }
      break;
    }
    case 'gemini': {
      for (const name of GEMINI_ENV_FILES) {
        add(name, envFileRoutingNames(readText(path.join(workspace, name))));
      }
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
 * refused: it would have to be edited.
 */
export function strictClaudeSettingsArgs(workspace: string, configDir: string | undefined): string[] {
  if (configDir) {
    const userSettingsPath = path.join(configDir, 'settings.json');
    const user = readJson(userSettingsPath);
    if (claudeRoutingSettings(user).length > 0) {
      if (isInside(workspace, configDir)) {
        throw new Error(checkoutSettingsRefusal(
          `The harness config directory ${path.relative(workspace, configDir)} in the checkout sets routing settings`,
        ));
      }
      fs.writeFileSync(userSettingsPath, JSON.stringify(cleanClaudeSettings(user), null, 2));
    }
  }
  const merged = mergeSettings(
    readJson(path.join(workspace, '.claude', 'settings.json')),
    readJson(path.join(workspace, '.claude', 'settings.local.json')),
  );
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eve-claude-settings-')), 'settings.json');
  fs.writeFileSync(file, JSON.stringify(cleanClaudeSettings(merged), null, 2), { mode: 0o600 });
  return ['--settings', file, '--setting-sources', 'user'];
}

/**
 * Codex under `strict`: `-c` overrides (the top config layer) that pin the
 * built-in OpenAI provider, which honours the job's own OPENAI_BASE_URL, for
 * the base config and the variant's profile. A checkout config that sets a
 * base URL outside a provider entry is refused, since no override undoes it.
 */
export function strictCodexArgs(workspace: string, codexHome: string | undefined, variant: string | undefined): string[] {
  const unremovable = findCheckoutRouting({ workspace, harness: 'codex', configDir: codexHome })
    .flatMap((finding) => finding.settings.filter((setting) => /base_url$/.test(setting)).map((setting) => `${finding.file}: ${setting}`));
  if (unremovable.length > 0) {
    throw new Error(checkoutSettingsRefusal(`The checkout's Codex config sets ${unremovable.join(', ')}`));
  }
  const args = ['-c', 'model_provider="openai"'];
  if (variant) args.push('-c', `profiles.${variant}.model_provider="openai"`);
  return args;
}

/**
 * Gemini under `strict`: the settings to put in Eve's system settings file
 * (which outranks workspace settings) so the project `.env` cannot set a
 * routing name. Routing names in `.gemini/.env`, which Gemini loads whatever
 * the exclusions, are refused.
 */
export function strictGeminiSystemSettings(workspace: string): { advanced: { excludedEnvVars: string[] } } {
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
 * dotted name: `model_provider` (also a profile's), each `model_providers`
 * entry, and any key ending `base_url`. A line scan, enough to name them.
 */
function codexRoutingSettings(text: string | null): string[] {
  if (!text) return [];
  const settings = new Set<string>();
  let table = '';
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line || line.startsWith('#')) continue;
    const header = /^\[\[?\s*(.+?)\s*\]\]?$/.exec(line);
    if (header) {
      table = unquote(header[1]);
      continue;
    }
    const assign = /^([A-Za-z0-9_."'-]+(?:\s*\.\s*[A-Za-z0-9_."'-]+)*)\s*=/.exec(line);
    if (!assign) continue;
    const key = [table, unquote(assign[1])].filter(Boolean).join('.');
    const provider = /^model_providers\.([^.]+)/.exec(key);
    if (provider) settings.add(`model_providers.${provider[1]}`);
    else if (/(^|\.)model_provider$/.test(key) || /base_url$/.test(key)) settings.add(key);
  }
  return [...settings];
}

function envFileRoutingNames(text: string | null): string[] {
  if (!text) return [];
  const names = new Set<string>();
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line);
    if (match && isCheckoutRoutingEnvKey(match[1])) names.add(match[1]);
  }
  return [...names].sort();
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

function unquote(dotted: string): string {
  return dotted.split('.').map((part) => part.trim().replace(/^["']|["']$/g, '')).join('.');
}

function readText(file: string): string | null {
  try {
    return fs.readFileSync(file, 'utf8');
  } catch {
    return null;
  }
}

function readJson(file: string): unknown {
  const text = readText(file);
  if (text === null) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
