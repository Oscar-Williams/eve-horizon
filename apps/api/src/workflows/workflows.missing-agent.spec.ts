import { describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import type { SecurityProfile } from '@eve/shared';
import { WorkflowsService } from './workflows.service.js';

/** The job queries an invoke's transaction gets: the test's own `jobs` mock. */
const txJobs = vi.hoisted(() => ({ current: null as unknown }));
vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return { ...actual, jobQueries: vi.fn(() => txJobs.current) };
});

const MANIFEST = `
name: test
workflows:
  triage:
    steps:
      - name: judge
        agent:
          name: triage
          prompt: Judge the batch
`;

function fakeSecurity(profile: SecurityProfile) {
  return {
    gate: vi.fn(async (rule: string, _ctx: unknown, message?: string) => {
      if (profile === 'legacy') return 'allowed';
      if (profile === 'strict') throw new ForbiddenException(`${message ?? 'Refused'} (rule ${rule})`);
      return 'recorded';
    }),
  };
}

function createService(profile: SecurityProfile, agents: Array<{ id: string }>) {
  const security = fakeSecurity(profile);
  const service = new WorkflowsService(
    { begin: vi.fn(async (work: (tx: unknown) => Promise<unknown>) => work({})) } as never,
    { can: async () => ({ allowed: true, source: 'test' }) } as never,
  );
  const created: Array<Record<string, unknown>> = [];
  Object.assign(service as unknown as Record<string, unknown>, {
    security,
    manifests: { findLatestByProject: vi.fn().mockResolvedValue({ manifest_yaml: MANIFEST }) },
    projects: { findById: vi.fn().mockResolvedValue({ id: 'proj_lab', org_id: 'org_acme', slug: 'lab' }) },
    jobs: {
      generateJobId: vi.fn().mockImplementation(() =>
        Promise.resolve({ id: `lab-${Math.random().toString(16).slice(2, 10).padEnd(8, '0')}`, projectId: 'proj_lab' })),
      create: vi.fn().mockImplementation((data: Record<string, unknown>) => {
        created.push(data);
        return Promise.resolve({ id: data.id, phase: 'ready' });
      }),
      addDependency: vi.fn().mockResolvedValue(undefined),
      updatePhase: vi.fn().mockResolvedValue({ success: true }),
    },
    agents: { listByProject: vi.fn().mockResolvedValue(agents) },
    agentConfigs: { findLatestByProject: vi.fn().mockResolvedValue(null) },
    apiSources: { list: vi.fn().mockResolvedValue([]) },
    appLinkSubscriptions: {
      listByConsumer: vi.fn().mockResolvedValue([]),
      listWithGrants: vi.fn().mockResolvedValue([]),
    },
  });
  txJobs.current = (service as unknown as { jobs: unknown }).jobs;
  return { service, security, created };
}

describe('WorkflowsService.invoke: a step that names an agent that does not exist', () => {
  it('fails under strict before any job is created', async () => {
    const { service, security, created } = createService('strict', []);

    await expect(service.invoke('proj_lab', 'triage', { input: {} })).rejects.toBeInstanceOf(ForbiddenException);
    expect(security.gate).toHaveBeenCalledWith('harness.missing_agent', expect.objectContaining({
      projectId: 'proj_lab',
      governing: 'project',
      detail: expect.objectContaining({ workflow: 'triage', step: 'judge', agent: 'triage' }),
    }), expect.any(String));
    expect(created.filter((job) => job.step_name === 'judge')).toEqual([]);
  });

  it('runs under audit and records a finding', async () => {
    const { service, security, created } = createService('audit', []);

    await service.invoke('proj_lab', 'triage', { input: {} });

    expect(security.gate).toHaveBeenCalledWith('harness.missing_agent', expect.anything(), expect.any(String));
    expect(created.find((job) => job.step_name === 'judge')?.assignee).toBeNull();
  });

  it('decides nothing when the agent exists', async () => {
    const { service, security, created } = createService('strict', [{ id: 'triage' }]);

    await service.invoke('proj_lab', 'triage', { input: {} });

    expect(security.gate).not.toHaveBeenCalled();
    expect(created.find((job) => job.step_name === 'judge')?.assignee).toBe('triage');
  });
});
