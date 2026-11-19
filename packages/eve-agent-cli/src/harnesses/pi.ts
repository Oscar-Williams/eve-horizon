import { CHECKOUT_SETTINGS_ENV, checkoutSettingsRefusal } from '@eve/shared';
import type { CliHarnessAdapter, CliContext, HarnessCommand } from './types.js';

export function buildPiCommand(ctx: CliContext): { command: HarnessCommand; warnings: string[] } {
  if (ctx.env[CHECKOUT_SETTINGS_ENV] === 'strict') {
    throw new Error(checkoutSettingsRefusal('pi has no confirmed way to keep checkout settings from rerouting it'));
  }
  const warnings: string[] = [];
  const args: string[] = [];
  const env: Record<string, string | undefined> = { ...ctx.env };

  // Non-interactive JSON streaming mode (no session persistence)
  args.push('--mode', 'json');
  args.push('--no-session');

  // Disable extension/skill/theme auto-discovery in containerized env
  args.push('--no-extensions', '--no-themes', '--no-prompt-templates');

  // Model selection — pi uses provider/model prefix: --model openai/gpt-4o
  if (ctx.model) {
    args.push('--model', ctx.model);
  }

  // Thinking/reasoning level (already mapped by shared adapter)
  if (ctx.reasoning) {
    args.push('--thinking', ctx.reasoning);
  }

  // Tool selection — pi defaults to read,bash,edit,write
  args.push('--tools', 'read,bash,edit,write,grep,find,ls');

  // Permission policy — pi runs autonomously (no built-in gates)
  if (ctx.permission !== 'yolo' && ctx.permission !== 'never') {
    warnings.push('pi has no built-in permission gates; running autonomously');
  }

  // Prompt is the last positional argument. pi has no stdin prompt mode, so
  // unlike the other harnesses its prompt is visible on the command line.
  args.push(ctx.prompt);

  return {
    command: {
      binary: 'pi',
      args,
      env,
    },
    warnings,
  };
}

export const piCliAdapter: CliHarnessAdapter = {
  name: 'pi',
  buildCommand: buildPiCommand,
};
