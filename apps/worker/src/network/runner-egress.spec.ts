import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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

  // A strict project's runner policies could not be written: a passing API
  // error (a timeout, a conflict, a restarting API server) should not fail
  // the attempt, so the sync is tried once more after a short wait.
  describe('a failed strict sync', () => {
    const syncError = () => Object.assign(new Error('the runner egress policies of project proj_shop could not be written: timeout'), {
      name: 'RunnerEgressSyncError',
    });

    beforeEach(() => {
      vi.useFakeTimers();
      vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    });

    afterEach(() => {
      vi.useRealTimers();
      vi.restoreAllMocks();
    });

    it('is tried once more after a short wait, and the job runs when that succeeds', async () => {
      const ensureRunnersForDispatch = vi.fn()
        .mockRejectedValueOnce(syncError())
        .mockResolvedValueOnce('written');
      registerRunnerEgress({ ensureRunnersForDispatch });

      const result = ensureRunnerEgress('proj_shop');
      await vi.runAllTimersAsync();

      await expect(result).resolves.toBeUndefined();
      expect(ensureRunnersForDispatch).toHaveBeenCalledTimes(2);
    });

    it('refuses the job when the second try fails too', async () => {
      const failure = syncError();
      const ensureRunnersForDispatch = vi.fn().mockRejectedValue(failure);
      registerRunnerEgress({ ensureRunnersForDispatch });

      const result = ensureRunnerEgress('proj_shop');
      await vi.runAllTimersAsync();

      await expect(result).resolves.toBe(failure.message);
      expect(ensureRunnersForDispatch).toHaveBeenCalledTimes(2);
    });

    it('is not retried for a missing provider, which a second try cannot fix', async () => {
      const ensureRunnersForDispatch = vi.fn().mockRejectedValue(new EgressProviderMissingError());
      registerRunnerEgress({ ensureRunnersForDispatch });

      const result = ensureRunnerEgress('proj_shop');
      await vi.runAllTimersAsync();

      await expect(result).resolves.toMatch(/need a provider/);
      expect(ensureRunnersForDispatch).toHaveBeenCalledTimes(1);
    });
  });

  it('refuses the job when egress.allow_hosts is strict with no provider', async () => {
    registerRunnerEgress({ ensureRunnersForDispatch: vi.fn(async () => { throw new EgressProviderMissingError(); }) });
    await expect(ensureRunnerEgress('proj_shop')).resolves
      .toBe('egress allow lists need a provider (EVE_EGRESS_FQDN_PROVIDER) (rule egress.allow_hosts)');
  });
});
