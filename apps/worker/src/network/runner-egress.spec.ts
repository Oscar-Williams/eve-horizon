import { afterEach, describe, expect, it, vi } from 'vitest';
import { ensureRunnerEgress, registerRunnerEgress } from './runner-egress.js';

/**
 * The dispatch hook: before a runner pod starts, its project's runner
 * egress policies are brought in line with the profile. It never fails the
 * job (the static deny holds whatever happens), and does nothing until the
 * worker's network module has registered.
 */
afterEach(() => {
  registerRunnerEgress(null);
});

describe('ensureRunnerEgress', () => {
  it('does nothing before the network module registers', async () => {
    await expect(ensureRunnerEgress('proj_shop')).resolves.toBeUndefined();
  });

  it('brings the project set in line once registered, and skips work with no project', async () => {
    const ensureRunnersForDispatch = vi.fn(async () => 'written' as const);
    registerRunnerEgress({ ensureRunnersForDispatch });
    await ensureRunnerEgress('proj_shop');
    await ensureRunnerEgress(undefined);
    expect(ensureRunnersForDispatch).toHaveBeenCalledTimes(1);
    expect(ensureRunnersForDispatch).toHaveBeenCalledWith('proj_shop');
  });

  it('logs a failure and lets the job go on', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    registerRunnerEgress({ ensureRunnersForDispatch: vi.fn(async () => { throw new Error('forbidden'); }) });
    await expect(ensureRunnerEgress('proj_shop')).resolves.toBeUndefined();
    expect(warn).toHaveBeenCalledWith(expect.stringMatching(/proj_shop.*forbidden/));
    warn.mockRestore();
  });
});
