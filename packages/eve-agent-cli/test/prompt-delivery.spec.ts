import { describe, expect, it } from 'vitest';
import { resolveCliAdapter } from '../src/harnesses/index';
import type { CliContext, HarnessName } from '../src/harnesses/types';

const PROMPT = 'Triage notice 4471: untrusted text from a tender portal';

function context(harness: HarnessName): CliContext {
  return {
    harness,
    prompt: PROMPT,
    permission: 'yolo',
    model: harness === 'gemini' ? 'gemini-2.5-pro' : undefined,
    env: { PATH: process.env.PATH, OPENAI_API_KEY: 'sk-test' },
    workspace: '/workspace/repo',
  };
}

describe('harness prompt delivery', () => {
  // `ps` shows every argument to every user on the pod, so the prompt
  // travels on stdin for each harness whose CLI reads it from there.
  it.each<HarnessName>(['claude', 'mclaude', 'zai', 'codex', 'code', 'gemini'])(
    '%s receives the prompt on stdin, not argv',
    (harness) => {
      const { command } = resolveCliAdapter(harness)!.buildCommand(context(harness));

      expect(command.args.join(' ')).not.toContain(PROMPT);
      expect(command.stdin).toBe(PROMPT);
    },
  );

  it('codex reads its instructions from stdin through the "-" prompt argument', () => {
    const { command } = resolveCliAdapter('codex')!.buildCommand(context('codex'));

    expect(command.args.slice(-1)).toEqual(['-']);
  });
});
