import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { CHECKOUT_SETTINGS_ENV, strictGeminiSystemSettings } from '@eve/shared';
import type { CliHarnessAdapter } from './types';

const GEMINI_THINKING_BUDGET: Record<string, number> = {
  low: 1024,
  medium: 4096,
  high: 8192,
  'x-high': 16384,
};

const GEMINI_THINKING_LEVEL: Record<string, string> = {
  low: 'low',
  medium: 'low',
  high: 'high',
  'x-high': 'high',
};

function isGemini3Model(model?: string): boolean {
  if (!model) return true;
  return model.includes('gemini-3');
}

function buildThinkingConfig(reasoning: string, model?: string): Record<string, unknown> | null {
  if (!['low', 'medium', 'high', 'x-high'].includes(reasoning)) return null;
  if (isGemini3Model(model)) {
    return {
      thinkingLevel: GEMINI_THINKING_LEVEL[reasoning],
      includeThoughts: true,
    };
  }
  return {
    thinkingBudget: GEMINI_THINKING_BUDGET[reasoning],
    includeThoughts: true,
  };
}

export const geminiAdapter: CliHarnessAdapter = {
  name: 'gemini',
  buildCommand: (ctx) => {
    const env = { ...ctx.env };
    const args = ['--output-format', 'stream-json'];
    const warnings: string[] = [];

    // Sandbox: enable sandbox mode to restrict file operations to workspace
    // This prevents directory traversal attacks when multiple jobs share a worker
    args.push('--sandbox');

    if (ctx.model) {
      args.push('--model', ctx.model);
    }

    // An Eve-owned system settings file, which outranks workspace settings.
    // Rule harness.checkout_settings under strict: the project .env may not
    // set a routing name.
    let systemSettings: Record<string, unknown> | null = env[CHECKOUT_SETTINGS_ENV] === 'strict'
      ? { ...strictGeminiSystemSettings(ctx.workspace) }
      : null;
    let settingsPath: string | null = null;
    const settingsFile = () =>
      (settingsPath ??= path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'eve-gemini-')), 'settings.json'));

    if (ctx.reasoning) {
      if (!ctx.model) {
        warnings.push('Gemini reasoning requires --model; skipping reasoning config.');
      } else {
        const thinkingConfig = buildThinkingConfig(ctx.reasoning, ctx.model);
        if (!thinkingConfig) {
          warnings.push(`Gemini reasoning level "${ctx.reasoning}" not recognized; skipping.`);
        } else {
          const file = settingsFile();
          let settings: Record<string, unknown> = {};
          try {
            if (fs.existsSync(file)) {
              settings = JSON.parse(fs.readFileSync(file, 'utf-8')) as Record<string, unknown>;
            }
          } catch {
            settings = {};
          }

          const modelConfigs = (settings.modelConfigs as Record<string, unknown> | undefined) ?? {};
          const overrides = Array.isArray(modelConfigs.overrides) ? modelConfigs.overrides : [];
          const filteredOverrides = overrides.filter((override) => {
            const match = (override as Record<string, unknown>)?.match as Record<string, unknown> | undefined;
            return match?.model !== ctx.model;
          });

          const newOverride = {
            match: { model: ctx.model },
            modelConfig: {
              generateContentConfig: {
                thinkingConfig,
              },
            },
          };

          systemSettings = {
            ...settings,
            ...(systemSettings ?? {}),
            modelConfigs: {
              ...modelConfigs,
              overrides: [...filteredOverrides, newOverride],
            },
          };
        }
      }
    }

    if (systemSettings) {
      const file = settingsFile();
      fs.writeFileSync(file, JSON.stringify(systemSettings, null, 2));
      env.GEMINI_CLI_SYSTEM_SETTINGS_PATH = file;
    }

    if (ctx.permission === 'default') {
      args.push('--approval-mode', 'default');
    } else if (ctx.permission === 'auto_edit') {
      args.push('--approval-mode', 'auto_edit');
    } else if (ctx.permission === 'never') {
      warnings.push('Gemini does not support "never"; falling back to default.');
      args.push('--approval-mode', 'default');
    } else if (ctx.permission === 'yolo') {
      args.push('--yolo');
    }

    // With no positional query and stdin not a TTY, gemini runs one-shot on stdin.
    return {
      command: { binary: 'gemini', args, env, stdin: ctx.prompt },
      warnings,
    };
  },
};
