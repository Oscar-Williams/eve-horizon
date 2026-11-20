import { afterEach, describe, expect, it, vi } from 'vitest';
import { EgressProviderMissingError } from '@eve/shared';
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

  it("refuses the job when a strict project's runner policies could not be written", async () => {
    const failure = Object.assign(new Error('the runner egress policies of project proj_shop could not be written: forbidden'), {
      name: 'RunnerEgressSyncError',
    });
    registerRunnerEgress({ ensureRunnersForDispatch: vi.fn(async () => { throw failure; }) });
    await expect(ensureRunnerEgress('proj_shop')).resolves.toBe(failure.message);
  });

  it('refuses the job when egress.allow_hosts is strict with no provider', async () => {
    registerRunnerEgress({ ensureRunnersForDispatch: vi.fn(async () => { throw new EgressProviderMissingError(); }) });
    await expect(ensureRunnerEgress('proj_shop')).resolves
      .toBe('egress allow lists need a provider (EVE_EGRESS_FQDN_PROVIDER) (rule egress.allow_hosts)');
  });
});
