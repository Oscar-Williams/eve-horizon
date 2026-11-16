import { UnauthorizedException } from '@nestjs/common';
import type { jobQueries } from '@eve/db';

type JobLookup = Pick<ReturnType<typeof jobQueries>, 'findById' | 'getCurrentAttempt'>;

/**
 * Tokens minted for a job (its job token, and app-link tokens with a
 * `job:<id>` principal) work only while the job runs:
 *
 * - bound to an attempt (`attempt_id` claim): while that attempt is the job's
 *   running attempt;
 * - minted without one: until the job is done.
 *
 * A cancelled job's tokens stop at once, before its attempt is recorded as
 * ended. A job token lasts up to a day and an app-link token an hour, so
 * without this check either would outlive the job that held it.
 */
export async function assertJobRunning(jobs: JobLookup, jobId: string, attemptId?: string): Promise<void> {
  const job = await jobs.findById(jobId);
  if (!job) {
    throw new UnauthorizedException('Token job not found');
  }
  if (job.phase === 'cancelled') {
    throw new UnauthorizedException('Token job was cancelled');
  }
  if (attemptId) {
    const running = await jobs.getCurrentAttempt(jobId);
    if (running?.id !== attemptId) {
      throw new UnauthorizedException('Token job attempt has ended');
    }
    return;
  }
  if (job.phase === 'done') {
    throw new UnauthorizedException('Token job has ended');
  }
}

/** Whether `attemptId` is the job's running attempt (for binding a token to it at mint). */
export async function isRunningAttempt(jobs: JobLookup, jobId: string, attemptId: string): Promise<boolean> {
  const running = await jobs.getCurrentAttempt(jobId);
  return running?.id === attemptId;
}
