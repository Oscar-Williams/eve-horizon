import type { RunnerApiClient, RunnerResultReport, RunnerSubmit } from '@eve/shared';

export const RUNNER_SELF_CHECK = 'RUNNER_SELF_CHECK';

/** Runs before the job's token is used; returns a failed result to refuse the job. */
export type RunnerSelfCheck = (submit: RunnerSubmit, client: RunnerApiClient) => Promise<RunnerResultReport | null>;

/** Phase 1 has no egress self-check; the runner takes every authenticated submit. */
export const noSelfCheck: RunnerSelfCheck = async () => null;
