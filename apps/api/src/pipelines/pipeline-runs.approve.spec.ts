import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { PipelineRunsService } from './pipeline-runs.service';
import { PipelineRunsController } from './pipeline-runs.controller';
import { SecurityService } from '../security/security.service';
import type { AuthUser } from '../auth/auth.types';

const m = vi.hoisted(() => ({
  projectProfile: null as string | null,
  findings: [] as Array<Record<string, unknown>>,
  runs: {
    findRunById: vi.fn(),
    updateRun: vi.fn(async () => undefined),
    listStepRuns: vi.fn(async () => [{ id: 'step_1', status: 'blocked' }]),
    updateStepRun: vi.fn(async () => undefined),
  },
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    pipelineRunQueries: vi.fn(() => m.runs),
    systemSettingsQueries: vi.fn(() => ({ get: vi.fn(async () => null) })),
    securityQueries: vi.fn(() => ({
      getProfiles: vi.fn(async () => ({ org_id: 'org_a', org_profile: null, project_profile: m.projectProfile })),
      recordFinding: vi.fn(async (finding: Record<string, unknown>) => {
        m.findings.push(finding);
      }),
    })),
  };
});

/** Records the raw statements the service writes (the audit row). */
const statements: Array<{ sql: string; values: unknown[] }> = [];
const db = Object.assign(
  async (strings: TemplateStringsArray, ...values: unknown[]) => {
    statements.push({ sql: strings.join('?'), values });
    return [];
  },
  { json: (v: unknown) => v },
);

function controller(): PipelineRunsController {
  const Service = PipelineRunsService as unknown as new (...args: unknown[]) => PipelineRunsService;
  const service = new Service(db, {} as never, new SecurityService({} as never));
  (service as unknown as { getRunDetail: () => Promise<unknown> }).getRunDetail = vi.fn(async () => ({ id: 'prun_1' }));
  return new PipelineRunsController(service);
}

function approve(caller: AuthUser): Promise<unknown> {
  const c = controller();
  return (c.approveRun as unknown as (...a: unknown[]) => Promise<unknown>).call(c, 'prun_1', caller);
}

const MEMBER: AuthUser = { user_id: 'user_mate' };
const DEPLOY_STEP: AuthUser = {
  user_id: 'user_owner',
  is_job_token: true,
  job_id: 'a-deploy',
  org_id: 'org_a',
  project_id: 'proj_a',
  permissions: ['pipelines:read', 'pipelines:write'],
};

beforeEach(() => {
  vi.clearAllMocks();
  statements.length = 0;
  m.projectProfile = null;
  m.findings = [];
  m.runs.findRunById.mockResolvedValue({
    id: 'prun_1',
    project_id: 'proj_a',
    pipeline_name: 'deploy',
    env_name: 'prod',
    status: 'awaiting_approval',
    run_mode: null,
    inputs_json: { approved_envs: [] },
  });
});

describe('approving a pipeline run', () => {
  it('records the caller as the decider', async () => {
    await approve(MEMBER);

    expect(m.runs.updateRun).toHaveBeenCalledWith('prun_1', {
      status: 'pending',
      inputs_json: { approved_envs: ['prod'], approved_by: 'user_mate' },
    });
    const audit = statements.find((s) => /INSERT INTO audit_log/.test(s.sql));
    expect(audit?.values).toEqual(expect.arrayContaining(['pipeline_run', 'prun_1', 'user_mate', 'user']));
  });

  it('records a job token as its job and, under audit, records a finding', async () => {
    m.projectProfile = 'audit';

    await approve(DEPLOY_STEP);

    expect(m.runs.updateRun).toHaveBeenCalledWith('prun_1', expect.objectContaining({
      inputs_json: expect.objectContaining({ approved_by: 'job:a-deploy' }),
    }));
    expect(m.findings.filter((f) => f.rule === 'pipelines.approve_token')).toHaveLength(1);
  });

  it('refuses a job token under strict and changes nothing, but accepts a person', async () => {
    m.projectProfile = 'strict';

    await expect(approve(DEPLOY_STEP)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.runs.updateRun).not.toHaveBeenCalled();

    await approve(MEMBER);
    expect(m.runs.updateRun).toHaveBeenCalledTimes(1);
  });
});
