import { describe, expect, it, vi } from 'vitest';
import { LoopService } from './loop.service';

type Row = Record<string, unknown>;

type LoopInternals = {
  evaluateStepCondition(jobs: unknown, job: Row): Promise<{ shouldRun: boolean; reason?: string } | null>;
};

function loop(): LoopInternals {
  const service = Object.create(LoopService.prototype) as Row;
  service.logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
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
  };
}

const SAID_OK = { status: 'succeeded', result_json: { eve: { status: 'ok' } } };

describe('a workflow step condition', () => {
  it('is evaluated when its source step is done with a completed latest attempt', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('done'), SAID_OK), writeStep("research.status == 'ok'"));

    expect(outcome).toEqual({ shouldRun: true, reason: undefined });
  });

  it('is not met when its source step was cancelled, whatever that step last reported', async () => {
    const outcome = await loop().evaluateStepCondition(
      jobsWith(research('cancelled'), { status: 'cancelled', result_json: { eve: { status: 'ok' } } }),
      writeStep("research.status == 'ok'"),
    );

    expect(outcome?.shouldRun).toBe(false);
    expect(outcome?.reason).toMatch(/research/);
  });

  it('is not met when its source step was closed as done with no attempt', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('done'), null), writeStep("research.status != 'skip'"));

    expect(outcome?.shouldRun).toBe(false);
  });

  it("is not met when its source step's latest attempt did not complete", async () => {
    const outcome = await loop().evaluateStepCondition(
      jobsWith(research('done'), { status: 'running', result_json: null }),
      writeStep("research.status != 'skip'"),
    );

    expect(outcome?.shouldRun).toBe(false);
  });

  it('is not met, rather than left waiting, when its source step has not finished', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('active'), null), writeStep("research.status != 'skip'"));

    expect(outcome?.shouldRun).toBe(false);
  });

  it('is not met when its source step cannot be found', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(null, null), writeStep("research.status != 'skip'"));

    expect(outcome?.shouldRun).toBe(false);
  });

  it('is not met when it cannot be read', async () => {
    const outcome = await loop().evaluateStepCondition(jobsWith(research('done'), SAID_OK), writeStep('research is fine'));

    expect(outcome?.shouldRun).toBe(false);
  });
});
