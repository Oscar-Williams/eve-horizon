import { UnauthorizedException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { assertJobRunning, isRunningAttempt } from './job-liveness';

/** Only the one narrow lookup: a full job row and attempt row per request are not needed. */
function lookup(state: { phase: string; running_attempt_id: string | null } | null) {
  return { getTokenLiveness: vi.fn(async () => state) };
}

describe('job token liveness', () => {
  it('reads phase and running attempt in one narrow lookup', async () => {
    const jobs = lookup({ phase: 'active', running_attempt_id: 'att-1' });

    await assertJobRunning(jobs as never, 'opps-1', 'att-1');

    expect(jobs.getTokenLiveness).toHaveBeenCalledTimes(1);
    expect(jobs.getTokenLiveness).toHaveBeenCalledWith('opps-1');
  });

  it('refuses an ended attempt, a cancelled job, a done job and a missing job', async () => {
    await expect(assertJobRunning(lookup({ phase: 'active', running_attempt_id: 'att-2' }) as never, 'j', 'att-1')).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(assertJobRunning(lookup({ phase: 'cancelled', running_attempt_id: 'att-1' }) as never, 'j', 'att-1')).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(assertJobRunning(lookup({ phase: 'done', running_attempt_id: null }) as never, 'j')).rejects.toBeInstanceOf(UnauthorizedException);
    await expect(assertJobRunning(lookup(null) as never, 'j')).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('checks a mint-time attempt with the same lookup', async () => {
    await expect(isRunningAttempt(lookup({ phase: 'active', running_attempt_id: 'att-1' }) as never, 'j', 'att-1')).resolves.toBe(true);
    await expect(isRunningAttempt(lookup({ phase: 'active', running_attempt_id: null }) as never, 'j', 'att-1')).resolves.toBe(false);
  });
});
