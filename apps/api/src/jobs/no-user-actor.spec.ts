import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AccessService } from '../auth/access.service';
import { WorkflowsService } from '../workflows/workflows.service';
import { WorkflowsController } from '../workflows/workflows.controller';
import { PipelineExpanderService } from '../pipelines/pipeline-expander.service';
import { PipelineExpanderInternalController } from '../pipelines/pipeline-expander.internal.controller';
import { JobsService } from './jobs.service';
import { JobBatchService } from './job-batch.service';
import type { AuthUser } from '../auth/auth.types';

/**
 * Work no user started has no actor (R8-L). A job token for such work, and
 * internal pipeline expansion, carry the user id `'system'`; the jobs that
 * work creates store a null actor, never the text `'system'`.
 */

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
        script:
          run: "true"
pipelines:
  release:
    steps:
      - name: run
        action:
          type: run
          command: "true"
`;

const m = vi.hoisted(() => {
  const jobs: Array<Record<string, unknown>> = [];
  let n = 0;
  return {
    jobs,
    projects: {
      findById: vi.fn(async (id: string) => (id === 'proj_shop' ? { id: 'proj_shop', org_id: 'org_acme', slug: 'shop', name: 'shop' } : null)),
    },
    manifests: {
      findByProjectAndGitSha: vi.fn(async () => null),
      findLatestByProject: vi.fn(async () => ({ manifest_yaml: '', manifest_hash: 'h', parsed_defaults: null })),
    },
    runs: {
      createRun: vi.fn(async (d: Record<string, unknown>) => ({ ...d, created_at: new Date(), updated_at: new Date() })),
      findActiveRunByDedupeKey: vi.fn(async () => null),
    },
    batches: {
      findByIdempotencyKey: vi.fn(async () => null),
      create: vi.fn(async (d: Record<string, unknown>) => d),
    },
    jobQ: {
      resolveProjectSlug: vi.fn(async () => 'proj_shop'),
      generateJobId: vi.fn(async (_p: string, parentId?: string) => ({ id: parentId ? `${parentId}.${++n}` : `shop-${++n}`, projectId: 'proj_shop' })),
      create: vi.fn(async (d: Record<string, unknown>) => {
        jobs.push(d);
        return { ...d, created_at: new Date(), updated_at: new Date() };
      }),
      addDependency: vi.fn(async () => 'rel'),
      updatePhase: vi.fn(async () => ({ success: true })),
      findById: vi.fn(async (id: string) => jobs.find((j) => j.id === id) ?? null),
    },
    appLinks: { listByConsumer: vi.fn(async () => []) },
    apiSources: { list: vi.fn(async () => []) },
  };
});

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    projectQueries: vi.fn(() => m.projects),
    projectManifestQueries: vi.fn(() => m.manifests),
    pipelineRunQueries: vi.fn(() => m.runs),
    batchJobQueries: vi.fn(() => m.batches),
    jobQueries: vi.fn(() => m.jobQ),
    appLinkSubscriptionQueries: vi.fn(() => m.appLinks),
    projectApiSourceQueries: vi.fn(() => m.apiSources),
  };
});

/** A tagged-template DB stand-in; `begin` runs the transaction body inline. */
function fakeDb(rowsFor: (sql: string) => unknown[]) {
  const tag = ((strings: TemplateStringsArray) => Promise.resolve(rowsFor(strings.join('?')))) as unknown as Record<string, unknown>;
  tag.json = (v: unknown) => v;
  tag.begin = async (fn: (tx: unknown) => unknown) => fn(tag);
  return tag as never;
}
const rawSql = fakeDb(() => []);

function access(): AccessService {
  return new AccessService({} as never, rawSql);
}

/** The token of a job no user started: it carries the user id 'system'. */
const NO_USER_JOB_TOKEN: AuthUser = {
  user_id: 'system',
  is_job_token: true,
  job_id: 'shop-0',
  project_id: 'proj_shop',
  org_id: 'org_acme',
  permissions: ['jobs:read', 'jobs:write', 'workflows:write'],
} as AuthUser;

/** A finished workflow run with one step to retry. */
function retryDb() {
  const root = { id: 'shop-root', project_id: 'proj_shop', hints: { workflow_root: true }, phase: 'done', labels: [] };
  const child = {
    id: 'shop-root.1', project_id: 'proj_shop', parent_id: 'shop-root', depth: 1, step_name: 'count', phase: 'done',
    title: 't', description: 'd', issue_type: 'task', labels: [], priority: 0, hints: {}, execution_type: 'script',
    assignee: null, actor_user_id: null, token_permissions: null, token_scope: null, review_required: 'none',
  };
  m.jobs.push(root);
  return fakeDb((sql) => {
    if (sql.includes('FOR UPDATE') && sql.includes('WHERE id =')) return [root];
    if (sql.includes('WHERE parent_id')) return [child];
    if (sql.includes('RETURNING')) return [root];
    return [];
  });
}

function actors(): unknown[] {
  return m.jobs.map((job) => job.actor_user_id);
}

beforeEach(() => {
  vi.clearAllMocks();
  m.jobs.length = 0;
  m.manifests.findLatestByProject.mockResolvedValue({ manifest_yaml: MANIFEST, manifest_hash: 'h', parsed_defaults: null });
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
});

describe('jobs that work no user started creates store no actor', () => {
  it('on a workflow invoked with a no-user job token: the root and every step', async () => {
    const controller = new WorkflowsController(new WorkflowsService(rawSql, access()), {} as never);

    await controller.invoke('proj_shop', 'restock', {} as never, NO_USER_JOB_TOKEN);

    expect(m.jobs.map((job) => job.step_name ?? 'root')).toEqual(['root', 'count', 'order']);
    expect(actors()).toEqual([null, null, null]);
  });

  it('on job create', async () => {
    const jobsService = new JobsService(rawSql, {} as never, {} as never, {} as never, access());

    await jobsService.create('proj_shop', { description: 'restock the shelves' } as never, 'system', 'corr');

    expect(actors()).toEqual([null]);
  });

  it('on batch create', async () => {
    const batches = new JobBatchService(rawSql);

    await batches.createBatch(
      'proj_shop',
      { nodes: [{ key: 'a', title: 'count' }, { key: 'b', title: 'order' }], dependencies: [{ job: 'b', depends_on: ['a'] }] } as never,
      'corr',
      'system',
    );

    expect(actors()).toEqual([null, null]);
  });

  it('on internal pipeline expansion', async () => {
    const controller = new PipelineExpanderInternalController(new PipelineExpanderService(rawSql, access()));

    await controller.createRun('proj_shop', 'release', { git_sha: 'abc' });

    expect(m.jobs.length).toBeGreaterThan(0);
    expect([...new Set(actors())]).toEqual([null]);
  });

  it('on a workflow retry with a no-user job token', async () => {
    const controller = new WorkflowsController(new WorkflowsService(retryDb(), access()), {} as never);

    await controller.retry('proj_shop', { root_job_id: 'shop-root', from_step: 'count' } as never, NO_USER_JOB_TOKEN);

    const retried = m.jobs.find((job) => job.id !== 'shop-root' && job.step_name === 'count');
    expect(retried).toBeDefined();
    expect(retried?.actor_user_id).toBeNull();
  });

  it("but a person's own work keeps the person", async () => {
    const jobsService = new JobsService(rawSql, {} as never, {} as never, {} as never, access());

    await jobsService.create('proj_shop', { description: 'restock the shelves' } as never, 'user_alice', 'corr');

    expect(actors()).toEqual(['user_alice']);
  });
});
