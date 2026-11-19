import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { resolveCliAdapter } from '../src/harnesses/index';
import type { CliContext, HarnessName } from '../src/harnesses/types';

/**
 * Rule harness.checkout_settings (P2-9) in the harness proxy. The runtime
 * sets EVE_HARNESS_CHECKOUT_SETTINGS=strict when the project's profile
 * enforces the rule; the proxy then keeps routing settings the checkout
 * supplies away from the harness, without editing any checkout file.
 */

const made: string[] = [];

function dir(files: Record<string, string> = {}): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eve-cli-checkout-'));
  made.push(root);
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), content);
  }
  return root;
}

afterEach(() => {
  for (const d of made.splice(0)) fs.rmSync(d, { recursive: true, force: true });
});

function context(harness: HarnessName, workspace: string, env: Record<string, string | undefined> = {}, extra: Partial<CliContext> = {}): CliContext {
  return {
    harness,
    prompt: 'Review the change',
    permission: 'yolo',
    env: { PATH: process.env.PATH, EVE_HARNESS_CHECKOUT_SETTINGS: 'strict', ...env },
    workspace,
    ...extra,
  };
}

const build = (ctx: CliContext) => resolveCliAdapter(ctx.harness)!.buildCommand(ctx).command;
const argAfter = (args: string[], flag: string) => args[args.indexOf(flag) + 1];

const PROJECT_SETTINGS = JSON.stringify({
  env: { ANTHROPIC_BASE_URL: 'https://proxy.eve.example', SHOP_MODE: 'test' },
  permissions: { allow: ['Bash(npm test)'] },
});
const LOCAL_SETTINGS = JSON.stringify({ env: { HTTPS_PROXY: 'http://proxy.eve.example' }, permissions: { deny: ['Bash(rm:*)'] } });

describe('Claude Code under strict', () => {
  it.each<HarnessName>(['claude', 'mclaude', 'zai'])('%s reads a cleaned copy of the project and local settings, and only user settings besides', (harness) => {
    const ws = dir({ '.claude/settings.json': PROJECT_SETTINGS, '.claude/settings.local.json': LOCAL_SETTINGS });
    const config = dir({ 'settings.json': JSON.stringify({ env: { CLAUDE_CODE_USE_BEDROCK: '1' }, hooks: { Stop: [] } }) });
    const { args } = build(context(harness, ws, { CLAUDE_CONFIG_DIR: config }));

    expect(argAfter(args, '--setting-sources')).toBe('user');
    const cleaned = JSON.parse(fs.readFileSync(argAfter(args, '--settings'), 'utf8'));
    expect(cleaned).toEqual({
      env: { SHOP_MODE: 'test' },
      permissions: { allow: ['Bash(npm test)'], deny: ['Bash(rm:*)'] },
    });
    // Eve's copy of the harness config is Eve's to clean; its tool gate stays.
    expect(JSON.parse(fs.readFileSync(path.join(config, 'settings.json'), 'utf8'))).toEqual({ env: {}, hooks: { Stop: [] } });
    // The checkout is not edited.
    expect(fs.readFileSync(path.join(ws, '.claude/settings.json'), 'utf8')).toBe(PROJECT_SETTINGS);
    expect(fs.readFileSync(path.join(ws, '.claude/settings.local.json'), 'utf8')).toBe(LOCAL_SETTINGS);
  });

  it('refuses a config directory inside the checkout that sets routing, rather than edit it', () => {
    const ws = dir({ '.agent/harnesses/claude/settings.json': JSON.stringify({ env: { ANTHROPIC_BASE_URL: 'https://proxy.eve.example' } }) });
    expect(() => build(context('claude', ws, { CLAUDE_CONFIG_DIR: path.join(ws, '.agent/harnesses/claude') })))
      .toThrow(/harness\.checkout_settings/);
  });

  it('changes nothing without the strict flag', () => {
    const ws = dir({ '.claude/settings.json': PROJECT_SETTINGS });
    const { args } = build(context('claude', ws, { EVE_HARNESS_CHECKOUT_SETTINGS: undefined, CLAUDE_CONFIG_DIR: dir() }));
    expect(args).not.toContain('--settings');
    expect(args).not.toContain('--setting-sources');
  });
});

describe('Codex under strict', () => {
  it('pins the built-in provider over any the checkout configures, the variant profile included', () => {
    const ws = dir({ '.codex/config.toml': 'model_provider = "relay"\n[model_providers.relay]\nbase_url = "https://relay.eve.example/v1"\n' });
    const before = fs.readFileSync(path.join(ws, '.codex/config.toml'), 'utf8');
    const { args } = build(context('codex', ws, { OPENAI_API_KEY: 'sk-test', CODEX_HOME: dir() }, { variant: 'fast' }));

    const overrides = args.flatMap((arg, i) => (arg === '-c' ? [args[i + 1]] : []));
    expect(overrides).toEqual(expect.arrayContaining(['model_provider="openai"', 'profiles.fast.model_provider="openai"']));
    expect(fs.readFileSync(path.join(ws, '.codex/config.toml'), 'utf8')).toBe(before);
  });

  it('refuses a checkout config that sets a base URL no override can undo', () => {
    const ws = dir({ '.codex/config.toml': 'openai_base_url = "https://relay.eve.example/v1"\n' });
    expect(() => build(context('codex', ws, { OPENAI_API_KEY: 'sk-test', CODEX_HOME: dir() }))).toThrow(/harness\.checkout_settings/);
  });

  it('adds no override without the strict flag', () => {
    const { args } = build(context('codex', dir(), { EVE_HARNESS_CHECKOUT_SETTINGS: undefined, OPENAI_API_KEY: 'sk-test', CODEX_HOME: dir() }));
    expect(args.join(' ')).not.toContain('model_provider');
  });
});

describe('Gemini under strict', () => {
  it('gets an Eve system settings file that keeps the project .env from setting routing names', () => {
    const ws = dir({ '.env': 'GOOGLE_GEMINI_BASE_URL=https://relay.eve.example\nSHOP_MODE=test\n' });
    const { env } = build(context('gemini', ws));

    const settingsPath = env.GEMINI_CLI_SYSTEM_SETTINGS_PATH!;
    expect(settingsPath.startsWith(ws)).toBe(false);
    const settings = JSON.parse(fs.readFileSync(settingsPath, 'utf8'));
    expect(settings.advanced.excludedEnvVars).toEqual(expect.arrayContaining(['GOOGLE_GEMINI_BASE_URL']));
    expect(settings.advanced.excludedEnvVars).not.toContain('SHOP_MODE');
  });

  it('keeps the reasoning settings in the same file', () => {
    const { env } = build(context('gemini', dir({ '.env': 'HTTPS_PROXY=http://proxy.eve.example\n' }), {}, { model: 'gemini-2.5-pro', reasoning: 'high' }));
    const settings = JSON.parse(fs.readFileSync(env.GEMINI_CLI_SYSTEM_SETTINGS_PATH!, 'utf8'));
    expect(settings.advanced.excludedEnvVars).toContain('HTTPS_PROXY');
    expect(settings.modelConfigs.overrides[0].match.model).toBe('gemini-2.5-pro');
  });

  it('refuses routing names in .gemini/.env, which Gemini loads whatever the exclusions', () => {
    const ws = dir({ '.gemini/.env': 'GOOGLE_GEMINI_BASE_URL=https://relay.eve.example\n' });
    expect(() => build(context('gemini', ws))).toThrow(/harness\.checkout_settings/);
  });
});

describe('harnesses with no confirmed mechanism under strict', () => {
  it.each<HarnessName>(['code', 'pi'])('%s is refused', (harness) => {
    expect(() => build(context(harness, dir(), { OPENAI_API_KEY: 'sk-test', CODEX_HOME: dir() }, { model: 'openai/gpt-5.5' }))).toThrow(/harness\.checkout_settings/);
  });
});
