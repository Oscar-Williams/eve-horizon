import type { Job } from '@eve/db';
import type { AuthUser } from '../auth/auth.types.js';
import { describeActor } from '../security/security.service.js';

/** Security rule: a run's jobs change only through their run (governed by the project). */
export const RUN_STEP_CHANGE_RULE = 'jobs.run_step_change';

/** Security rule: a job outside any run changes its dependencies only for those who may change it (governed by the project). */
export const DEPENDENCY_CHANGE_RULE = 'jobs.dependency_change';

/**
 * The workflow or pipeline run a job belongs to, read from its record, never
 * from its id. `key` names the run; `rootId` is the workflow run's root job
 * (null for a pipeline run, which has none).
 */
export interface RunRef {
  key: string;
  rootId: string | null;
}

/**
 * The run of a job from its record: a compiled step (its `step_name`, which
 * only the workflow and pipeline expanders set) belongs to its pipeline run or
 * to the workflow run whose root is its parent; a job with compiled steps
 * under it (`isRoot`) is that workflow run's root. Any other job is in no run.
 */
export function runOfRecord(
  job: Pick<Job, 'id' | 'parent_id' | 'run_id' | 'step_name'>,
  isRoot: boolean,
): RunRef | null {
  if (job.step_name) {
    if (job.run_id) return { key: `pipeline:${job.run_id}`, rootId: null };
    if (job.parent_id) return { key: `workflow:${job.parent_id}`, rootId: job.parent_id };
    return { key: `job:${job.id}`, rootId: null };
  }
  return isRoot ? { key: `workflow:${job.id}`, rootId: job.id } : null;
}

/** What kind of run a job belongs to, for messages. */
export function runKind(run: RunRef): 'workflow' | 'pipeline' {
  return run.key.startsWith('pipeline:') ? 'pipeline' : 'workflow';
}

/** How to change what a run runs: retry a workflow, or start a new pipeline run. */
export function howToChangeRun(run: RunRef): string {
  return runKind(run) === 'pipeline'
    ? 'start a new pipeline run (eve pipeline run)'
    : 'retry the workflow (eve workflow retry)';
}

/** True for a person's own token: not a job, service, service-principal or app-link token. */
export function isUserToken(caller: AuthUser): boolean {
  return describeActor(caller)[0] === 'user';
}

/** Security rule: job approvals and rejections come from a person's own token (governed by the project). */
export const APPROVE_TOKEN_RULE = 'jobs.approve_token';

/** Security rule: pipeline-run approvals come from a person's own token (governed by the project). */
export const PIPELINE_APPROVE_TOKEN_RULE = 'pipelines.approve_token';

/**
 * Who made a decision, as recorded: a person's own token as the person; any
 * other token as its kind and id, so a job token is `job:<job id>`, never the
 * person whose job it is. `type` is the audit log's actor type.
 */
export function deciderOf(caller: AuthUser | undefined): { id: string; type: string } {
  if (!caller) {
    return { id: 'unauthenticated', type: 'system' };
  }
  const [kind, id] = describeActor(caller);
  if (kind === 'user') {
    return { id, type: 'user' };
  }
  return { id: `${kind}:${id}`, type: kind === 'job' ? 'agent' : kind };
}
