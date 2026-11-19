import { describe, expect, it, vi } from 'vitest';
import { LoopService } from './loop.service';

type Row = Record<string, unknown>;

type Outcome = { shouldRun: boolean; reason?: string; action?: 'skip' | 'fail' | 'wait' };

type LoopInternals = {
  evaluateStepCondition(jobs: unknown, job: Row): Promise<Outcome | null>;
  conditionAllowsClaim(jobs: unknown, job: Row): Promise<boolean>;
  db: ReturnType<typeof vi.fn>;
};

function loop(): LoopInternals {
  const service = Object.create(LoopService.prototype) as Row;
  service.logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() };
  service.db = vi.fn(async () => []);
  return service as unknown as LoopInternals;
}

/** Run run1, started by user_owner: "research", then "write", which runs only if research said ok. */
const RUN_ROOT: Row = { id: 'run1', parent_id: null, project_id: 'proj_a', step_name: null, actor_user_id: 'user_owner' };

function writeStep(condition: string): Row {
  return {
    id: 'run1.2',
    parent_id: 'run1',
    project_id: 'proj_a',
    step_name: 'write',
    actor_user_id: 'user_owner',
    hints: { workflow_name: 'report', step_name: 'write', condition },
  };
}

function research(phase: string): Row {
  return { id: 'run1.1', parent_id: 'run1', project_id: 'proj_a', phase, step_name: 'research', actor_user_id: 'user_owner', hints: { step_name: 'research' } };
}

function jobsWith(source: Row | null, latestAttempt: Row | null) {
  return {
    findById: vi.fn(async (id: string) => (id === RUN_ROOT.id ? RUN_ROOT : null)),
    getDependencies: vi.fn(async () => (source ? [source] : [])),
    getLatestAttempt: vi.fn(async () => latestAttempt),
    findSiblingByStepName: vi.fn(async () => null),
    markJobFailed: vi.fn(async () => null),
  };
}

const SAID_OK = { status: 'succeeded', result_json: { eve: { status: 'ok' } } };

describe('a workflow step condition', () => {
  it('is evaluated when its source step is done with a completed latest attempt', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('done'), SAID_OK), writeStep("research.status == 'ok'"));

    expect(outcome).toEqual({ shouldRun: true, reason: undefined });
  });

  it('skips the step when the condition is read and not met', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('done'), SAID_OK), writeStep("research.status != 'ok'"));

    expect(outcome).toMatchObject({ shouldRun: false, action: 'skip' });
  });

  it('fails the step when its source step was cancelled, whatever that step last reported', async () => {
    const outcome = await loop().evaluateStepCondition(
      jobsWith(research('cancelled'), { status: 'cancelled', result_json: { eve: { status: 'ok' } } }),
      writeStep("research.status == 'ok'"),
    );

    expect(outcome).toMatchObject({ shouldRun: false, action: 'fail' });
    expect(outcome?.reason).toMatch(/research/);
  });

  it('fails the step when its source step was closed as done with no attempt', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('done'), null), writeStep("research.status != 'skip'"));

    expect(outcome).toMatchObject({ shouldRun: false, action: 'fail' });
  });

  it("fails the step when its source step's latest attempt did not complete", async () => {
    const outcome = await loop().evaluateStepCondition(
      jobsWith(research('done'), { status: 'running', result_json: null }),
      writeStep("research.status != 'skip'"),
    );

    expect(outcome).toMatchObject({ shouldRun: false, action: 'fail' });
  });

  it('keeps the step waiting while its source step has not finished', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('active'), null), writeStep("research.status != 'skip'"));

    expect(outcome).toMatchObject({ shouldRun: false, action: 'wait' });
  });

  it('fails the step when its source step cannot be found', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(null, null), writeStep("research.status != 'skip'"));

    expect(outcome).toMatchObject({ shouldRun: false, action: 'fail' });
  });

  it('fails the step when it cannot be read', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('done'), SAID_OK), writeStep('research is fine'));

    expect(outcome).toMatchObject({ shouldRun: false, action: 'fail' });
  });
});

describe('a step whose condition decides it before it is claimed', () => {
  it('is failed, never closed as done, when its source finished with no readable result', async () => {
    const service = loop();
    const jobs = jobsWith(research('done'), null);

    await expect(service.conditionAllowsClaim(jobs, writeStep("research.status != 'pass'"))).resolves.toBe(false);

    expect(jobs.markJobFailed).toHaveBeenCalledWith('run1.2', expect.stringMatching(/research/));
    expect(service.db).not.toHaveBeenCalled();
  });

  it('is left waiting, neither failed nor closed, while its source has not finished', async () => {
    const service = loop();
    const jobs = jobsWith(research('active'), null);

    await expect(service.conditionAllowsClaim(jobs, writeStep("research.status != 'pass'"))).resolves.toBe(false);

    expect(jobs.markJobFailed).not.toHaveBeenCalled();
    expect(service.db).not.toHaveBeenCalled();
  });

  it('is closed as done when its condition is read and not met', async () => {
    const service = loop();
    const jobs = jobsWith(research('done'), SAID_OK);

    await expect(service.conditionAllowsClaim(jobs, writeStep("research.status != 'ok'"))).resolves.toBe(false);

    expect(service.db).toHaveBeenCalledTimes(1);
    expect(jobs.markJobFailed).not.toHaveBeenCalled();
  });

  it('may be claimed when its condition is met', async () => {
    await expect(loop().conditionAllowsClaim(jobsWith(research('done'), SAID_OK), writeStep("research.status == 'ok'"))).resolves.toBe(true);
  });
});
