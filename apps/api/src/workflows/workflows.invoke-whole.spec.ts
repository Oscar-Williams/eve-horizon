import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException } from '@nestjs/common';
import { WorkflowsService } from './workflows.service.js';

/**
 * A workflow run is written whole or not at all (R8-02). Every step is
 * resolved first (agents, token ceilings, git, inputs), and only then are the
 * root, the steps, their edges and their releases written, in one
 * transaction. A step that cannot be resolved leaves no root and no step.
 *
 * `jobQueries` on the transaction gives `txJobs`; on anything else `jobs`,
 * so the test can tell which connection wrote.
 */
const m = vi.hoisted(() => {
  let n = 0;
  const tx = { name: 'tx' };
  function queries() {
    const created: Array<Record<string, unknown>> = [];
    return {
      created,
      generateJobId: vi.fn(async (_project: string, parentId?: string) => ({
        id: parentId ? `${parentId}.${++n}` : `shop-${String(++n).padStart(8, '0')}`,
        projectId: 'proj_shop',
      })),
      create: vi.fn(async (row: Record<string, unknown>) => {
        created.push(row);
        return { ...row };
      }),
      addDependency: vi.fn(async () => 'rel_1'),
      updatePhase: vi.fn(async () => ({ success: true })),
    };
  }
  return { tx, jobs: queries(), txJobs: queries(), queries };
});

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    jobQueries: vi.fn((db: unknown) => (db === m.tx ? m.txJobs : m.jobs)),
  };
});

const MANIFEST = `
name: shop
workflows:
  restock:
    steps:
      - name: count
        script:
          run: "true"
      - name: order
        depends_on: [count]
        agent:
          name: buyer
          prompt: Order what ran out
`;

const CEILING_MANIFEST = `
name: shop
workflows:
  restock:
    steps:
      - name: count
        script:
          run: "true"
      - name: order
        depends_on: [count]
        permissions: [secrets:write]
        script:
          run: "true"
`;

function createService(manifestYaml: string, buyerToolchains: unknown = ['python']) {
  const db = { begin: vi.fn(async (work: (tx: unknown) => Promise<unknown>) => work(m.tx)) };
  const access = {
    can: vi.fn(async ({ permission }: { permission: string }) => ({ allowed: permission !== 'secrets:write', source: 'test' })),
    judgeJobScopeBindings: async () => ({ refused: [], inside: true }),
    judgeNoUserJobScope: async () => [],
  };
  const service = new WorkflowsService(db as never, access as never);
  Object.assign(service as unknown as Record<string, unknown>, {
    manifests: { findLatestByProject: vi.fn(async () => ({ manifest_yaml: manifestYaml })) },
    projects: { findById: vi.fn(async () => ({ id: 'proj_shop', org_id: 'org_acme', slug: 'shop' })) },
    agents: { listByProject: vi.fn(async () => [{ id: 'buyer', harness_profile: null, policies_json: null }]) },
    agentConfigs: {
      findLatestByProject: vi.fn(async () => ({ x_eve_yaml: null, parsed_agents: { buyer: { toolchains: buyerToolchains } } })),
    },
    apiSources: { list: vi.fn(async () => []) },
    appLinkSubscriptions: {
      listByConsumer: vi.fn(async () => []),
      listWithGrants: vi.fn(async () => []),
    },
  });
  return { service, db };
}

function writes(q: ReturnType<typeof m.queries>) {
  return q.create.mock.calls.length + q.addDependency.mock.calls.length + q.updatePhase.mock.calls.length;
}

beforeEach(() => {
  vi.clearAllMocks();
  m.jobs.created.length = 0;
  m.txJobs.created.length = 0;
});

describe('WorkflowsService.invoke writes a run whole or not at all', () => {
  it('leaves no root and no step when the second step fails agent resolution', async () => {
    const { service } = createService(MANIFEST, ['cobol']);

    await expect(service.invoke('proj_shop', 'restock', { input: {} })).rejects.toBeInstanceOf(BadRequestException);

    expect([...m.jobs.created, ...m.txJobs.created]).toEqual([]);
    expect(writes(m.jobs) + writes(m.txJobs)).toBe(0);
  });

  it("leaves no root and no step when the second step's permissions exceed the invoking user's", async () => {
    const { service } = createService(CEILING_MANIFEST);

    await expect(service.invoke('proj_shop', 'restock', { input: {} }, false, 'user_alice')).rejects.toThrow(/secrets:write/);

    expect([...m.jobs.created, ...m.txJobs.created]).toEqual([]);
    expect(writes(m.jobs) + writes(m.txJobs)).toBe(0);
  });

  it('writes the root, the steps, the edges and the releases in one transaction', async () => {
    const { service, db } = createService(MANIFEST);

    const result = await service.invoke('proj_shop', 'restock', { input: {} });

    expect(db.begin).toHaveBeenCalledTimes(1);
    expect(writes(m.jobs)).toBe(0);
    expect(m.txJobs.created.map((row) => row.step_name ?? 'root')).toEqual(['root', 'count', 'order']);
    expect(m.txJobs.created.slice(1).every((row) => row.phase === 'backlog')).toBe(true);
    expect(m.txJobs.addDependency).toHaveBeenCalledTimes(1);
    expect(m.txJobs.updatePhase).toHaveBeenCalledTimes(2);
    expect(m.txJobs.addDependency.mock.invocationCallOrder[0])
      .toBeLessThan(Math.min(...m.txJobs.updatePhase.mock.invocationCallOrder));
    expect(result).toMatchObject({ job_id: m.txJobs.created[0].id, status: 'active' });
  });
});
