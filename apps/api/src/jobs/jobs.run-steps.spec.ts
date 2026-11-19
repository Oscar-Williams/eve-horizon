import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { JobsService } from './jobs.service';
import { JobsController } from './jobs.controller';
import { AccessService } from '../auth/access.service';
import { SecurityService } from '../security/security.service';
import type { AuthUser } from '../auth/auth.types';

/**
 * Two workflow runs and some loose jobs in proj_a.
 *
 * Run A (root a-run) was started by user_owner: a-run.1 "research", then
 * a-run.2 "write", which depends on it. Runs B and C were started by no user
 * (an event trigger). b-run.9 sits under run B's root but was created through
 * the jobs API, so it is not one of the run's compiled steps.
 */
const m = vi.hoisted(() => {
  const now = new Date('2026-11-18T09:00:00Z');
  type Row = Record<string, unknown> & { id: string };

  function job(id: string, overrides: Record<string, unknown> = {}): Row {
    return {
      id,
      project_id: 'proj_a',
      parent_id: null,
      depth: 0,
      title: id,
      description: `work for ${id}`,
      issue_type: 'task',
      labels: [],
      phase: 'ready',
      priority: 2,
      assignee: null,
      review_required: 'none',
      review_status: null,
      reviewer: null,
      defer_until: null,
      due_at: null,
      ready_at: null,
      closed_at: null,
      close_reason: null,
      hints: {},
      harness: null,
      harness_profile: null,
      harness_options: null,
      token_scope: null,
      token_permissions: null,
      secrets_allowlist: null,
      user_secrets_excluded: false,
      run_id: null,
      step_name: null,
      execution_type: 'agent',
      execution_mode: 'ephemeral',
      env_name: null,
      actor_user_id: 'user_owner',
      failure_disposition: null,
      created_at: now,
      updated_at: now,
      ...overrides,
    };
  }

  function step(id: string, root: string, stepName: string, actor: string | null, overrides: Record<string, unknown> = {}): Row {
    return job(id, { parent_id: root, depth: 1, step_name: stepName, actor_user_id: actor, hints: { step_name: stepName }, ...overrides });
  }

  function seed(): Map<string, Row> {
    const rows = [
      job('a-run', { phase: 'active', hints: { workflow_root: true } }),
      step('a-run.1', 'a-run', 'research', 'user_owner'),
      step('a-run.2', 'a-run', 'write', 'user_owner', { phase: 'review', review_required: 'human', review_status: 'pending' }),
      job('b-run', { phase: 'active', actor_user_id: null, hints: { workflow_root: true } }),
      step('b-run.1', 'b-run', 'scan', null),
      step('b-run.2', 'b-run', 'judge', null),
      job('b-run.9', { parent_id: 'b-run', depth: 1, actor_user_id: null }),
      job('c-run', { phase: 'active', actor_user_id: null, hints: { workflow_root: true } }),
      step('c-run.1', 'c-run', 'scan', null),
      job('solo-1'),
      job('solo-2'),
      job('solo-sys', { actor_user_id: null }),
    ];
    return new Map(rows.map((row) => [row.id, row]));
  }

  const state = {
    jobs: seed(),
    projectProfile: null as string | null,
    findings: [] as Array<Record<string, unknown>>,
  };

  const live = (id: string) => {
    const row = state.jobs.get(id);
    return row ? { ...row } : null;
  };
  const setPhase = (id: string, phase: string) => {
    const row = state.jobs.get(id);
    if (row) row.phase = phase;
    return row ? { ...row } : null;
  };
  const attempt = (jobId: string) => ({
    id: `att-${jobId}`,
    job_id: jobId,
    attempt_number: 1,
    status: 'running',
    trigger_type: 'manual',
    harness: null,
    agent_id: 'agent',
    started_at: now,
    execution_started_at: null,
    ended_at: null,
    result_summary: null,
  });

  const jobQ = {
    resolveProjectSlug: vi.fn(async (input: string) => input),
    findById: vi.fn(async (id: string) => live(id)),
    generateJobId: vi.fn(async (projectId: string, parentId?: string) => ({ id: parentId ? `${parentId}.7` : 'a-new', projectId })),
    create: vi.fn(async (row: Record<string, unknown>) => job(row.id as string, row)),
    updatePhase: vi.fn(async (id: string, phase: string) => ({ success: true, job: setPhase(id, phase) })),
    cancelJob: vi.fn(async (id: string) => setPhase(id, 'cancelled')),
    addDependency: vi.fn(async () => 'rel_1'),
    removeDependency: vi.fn(async () => true),
    claim: vi.fn(async (id: string) => ({ success: true, attempt: attempt(id) })),
    release: vi.fn(async (id: string) => ({ success: true, job: setPhase(id, 'ready') })),
    submitForReview: vi.fn(async (id: string) => setPhase(id, 'review')),
    approveReview: vi.fn(async (id: string) => setPhase(id, 'done')),
    rejectReview: vi.fn(async (id: string) => setPhase(id, 'active')),
  };

  return { state, seed, jobQ };
});

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    jobQueries: vi.fn(() => m.jobQ),
    projectQueries: vi.fn(() => ({ findById: vi.fn(async () => ({ id: 'proj_a', org_id: 'org_a', slug: 'a' })) })),
    projectManifestQueries: vi.fn(() => ({ findLatestByProject: vi.fn(async () => null) })),
    appLinkSubscriptionQueries: vi.fn(() => ({ listByConsumer: vi.fn(async () => []) })),
    projectApiSourceQueries: vi.fn(() => ({ list: vi.fn(async () => []) })),
    gateQueries: vi.fn(() => ({ releaseGates: vi.fn(async () => undefined) })),
    systemSettingsQueries: vi.fn(() => ({ get: vi.fn(async () => null) })),
    securityQueries: vi.fn(() => ({
      getProfiles: vi.fn(async () => ({ org_id: 'org_a', org_profile: null, project_profile: m.state.projectProfile })),
      recordFinding: vi.fn(async (finding: Record<string, unknown>) => {
        m.state.findings.push(finding);
      }),
    })),
  };
});

/** Answers the two raw queries the service makes: the run-root probe and the actor row lock. */
const db = Object.assign(
  async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?');
    if (/WHERE parent_id = \?/.test(sql) && /step_name IS NOT NULL/.test(sql)) {
      return [...m.state.jobs.values()].filter((row) => row.parent_id === values[0] && row.step_name).map((row) => ({ id: row.id }));
    }
    if (/FOR UPDATE/.test(sql)) {
      const row = m.state.jobs.get(values[0] as string);
      return row ? [row] : [];
    }
    return [];
  },
  { json: (v: unknown) => v },
);
Object.assign(db, { begin: async <T>(work: (tx: unknown) => Promise<T>) => work(db) });

/** Holders of jobs:admin in proj_a. Scoped tokens hold their own permissions. */
const rbac = {
  resolveEffectivePermissions: vi.fn(async (user: AuthUser) => {
    if (user.is_job_token || user.is_service_token || user.is_service_principal) return new Set(user.permissions ?? []);
    return new Set(user.user_id === 'user_admin' ? ['jobs:read', 'jobs:write', 'jobs:admin'] : ['jobs:read', 'jobs:write']);
  }),
  requirePermissions: vi.fn(async () => undefined),
};

function controller(): JobsController {
  const access = new AccessService({} as never, (async () => []) as never);
  const Service = JobsService as unknown as new (...args: unknown[]) => JobsService;
  const service = new Service(db, {} as never, {} as never, {} as never, access, new SecurityService({} as never), rbac);
  return new JobsController(service, rbac as never);
}

/** Calls a route with the arguments Nest passes it. */
function route<T = unknown>(target: JobsController, method: keyof JobsController, ...args: unknown[]): Promise<T> {
  return (target[method] as unknown as (...a: unknown[]) => Promise<T>).apply(target, args);
}

const OWNER: AuthUser = { user_id: 'user_owner' };
const TEAMMATE: AuthUser = { user_id: 'user_mate' };
const ADMIN: AuthUser = { user_id: 'user_admin' };

function jobToken(jobId: string, userId: string): AuthUser {
  return {
    user_id: userId,
    is_job_token: true,
    job_id: jobId,
    org_id: 'org_a',
    project_id: 'proj_a',
    permissions: ['jobs:read', 'jobs:write'],
  };
}

/** Run A's research step, which runs as user_owner. */
const RUN_A_STEP = jobToken('a-run.1', 'user_owner');
/** An agent job of user_owner's outside any run. */
const OWNER_AGENT = jobToken('solo-1', 'user_owner');
/** Run B's scan step: no user started run B. */
const RUN_B_STEP = jobToken('b-run.1', 'system');
/** Run C's scan step: no user started run C either. */
const RUN_C_STEP = jobToken('c-run.1', 'system');
/** A job filed under run B's root through the jobs API. */
const FILED_UNDER_B = jobToken('b-run.9', 'system');

function findingsFor(rule: string) {
  return m.state.findings.filter((f) => f.rule === rule);
}

beforeEach(() => {
  vi.clearAllMocks();
  m.state.jobs = m.seed();
  m.state.projectProfile = null;
  m.state.findings = [];
});

describe('dependency edges of compiled run steps', () => {
  it("refuses to remove a run step's dependency, even for the run's actor", async () => {
    await expect(route(controller(), 'removeDependency', 'a-run.2', 'a-run.1', OWNER)).rejects.toBeInstanceOf(ConflictException);
    expect(m.jobQ.removeDependency).not.toHaveBeenCalled();
  });

  it('refuses to add a dependency to a run step', async () => {
    await expect(
      route(controller(), 'addDependency', 'a-run.2', { related_job_id: 'solo-1' }, OWNER),
    ).rejects.toBeInstanceOf(ConflictException);
    expect(m.jobQ.addDependency).not.toHaveBeenCalled();
  });

  it('still adds and removes dependencies between jobs outside a run', async () => {
    await route(controller(), 'addDependency', 'solo-1', { related_job_id: 'solo-2' }, TEAMMATE);
    await route(controller(), 'removeDependency', 'solo-1', 'solo-2', TEAMMATE);

    expect(m.jobQ.addDependency).toHaveBeenCalledWith('solo-1', 'solo-2', 'blocks');
    expect(m.jobQ.removeDependency).toHaveBeenCalledWith('solo-1', 'solo-2');
  });
});

describe('creating a job under a parent', () => {
  const under = (parentId: string, caller: AuthUser) =>
    route(controller(), 'create', 'proj_a', { description: 'child', parent_id: parentId }, caller, 'corr-1');

  it("refuses a teammate's job under another person's job", async () => {
    await expect(under('solo-1', TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(under('a-run.1', TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.create).not.toHaveBeenCalled();
  });

  it("lets the parent's actor, and their agents, add jobs under it", async () => {
    await under('solo-1', OWNER);
    await under('a-run.1', OWNER_AGENT);

    expect(m.jobQ.create).toHaveBeenCalledTimes(2);
  });

  it('lets an agent no user started add children under its own job', async () => {
    await under('solo-sys', jobToken('solo-sys', 'system'));

    expect(m.jobQ.create).toHaveBeenCalledWith(expect.objectContaining({ parent_id: 'solo-sys' }));
  });

  it("lets a no-user run's own steps add jobs under the run", async () => {
    await under('b-run', RUN_B_STEP);
    await under('b-run.2', RUN_B_STEP);

    expect(m.jobQ.create).toHaveBeenCalledTimes(2);
  });

  it("refuses another no-user run's token a job under run B", async () => {
    await expect(under('b-run.2', RUN_C_STEP)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(under('solo-sys', RUN_C_STEP)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.create).not.toHaveBeenCalled();
  });

  it("judges the run from the job records, not from the token's job id", async () => {
    await expect(under('b-run.2', FILED_UNDER_B)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.create).not.toHaveBeenCalled();
  });

  it('lets a project admin add a job under anyone', async () => {
    await under('a-run.1', ADMIN);
    await under('b-run.2', ADMIN);

    expect(m.jobQ.create).toHaveBeenCalledTimes(2);
  });
});

describe('changing a run step under the strict profile', () => {
  beforeEach(() => {
    m.state.projectProfile = 'strict';
  });

  const toDone = (jobId: string, caller: AuthUser) => route(controller(), 'update', jobId, { phase: 'done' }, caller);

  it("refuses a teammate's PATCH of a run step to done, and changes nothing", async () => {
    await expect(toDone('a-run.1', TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.updatePhase).not.toHaveBeenCalled();
    expect(findingsFor('jobs.run_step_change')).toHaveLength(1);
  });

  it("lets a step of the same run, the run's actor and a project admin change it", async () => {
    await toDone('a-run.1', jobToken('a-run.2', 'user_owner'));
    m.state.jobs = m.seed();
    await toDone('a-run.1', OWNER);
    m.state.jobs = m.seed();
    await toDone('a-run.1', ADMIN);

    expect(m.jobQ.updatePhase).toHaveBeenCalledTimes(3);
    expect(findingsFor('jobs.run_step_change')).toEqual([]);
  });

  it("refuses the actor's agents from outside the run", async () => {
    await expect(toDone('a-run.1', OWNER_AGENT)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("refuses run C's no-user token a change to run B, but not run B's own step", async () => {
    await expect(toDone('b-run.2', RUN_C_STEP)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(controller(), 'update', 'b-run.2', { description: 'judge differently' }, RUN_C_STEP)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.updatePhase).not.toHaveBeenCalled();

    await toDone('b-run.2', RUN_B_STEP);
    expect(m.jobQ.updatePhase).toHaveBeenCalledWith('b-run.2', 'done');
  });

  it("refuses a teammate's claim, release, submit, reject and review change on a run step", async () => {
    const c = controller();
    await expect(route(c, 'claim', 'a-run.1', { agent_id: 'mate' }, TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'release', 'a-run.1', { agent_id: 'mate' }, TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'submit', 'a-run.1', { summary: 'done' }, TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'reject', 'a-run.2', { reason: 'again' }, TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'update', 'a-run.1', { review_required: 'human' }, TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);

    for (const fn of [m.jobQ.claim, m.jobQ.release, m.jobQ.submitForReview, m.jobQ.rejectReview]) {
      expect(fn).not.toHaveBeenCalled();
    }
  });

  it("leaves cosmetic edits and jobs outside a run to the project's members", async () => {
    await route(controller(), 'update', 'a-run.1', { priority: 0 }, TEAMMATE);
    await toDone('solo-1', TEAMMATE);

    expect(m.jobQ.updatePhase).toHaveBeenCalledWith('solo-1', 'done');
    expect(findingsFor('jobs.run_step_change')).toEqual([]);
  });

  it('cancels the steps after a cancelled step', async () => {
    await route(controller(), 'update', 'a-run.1', { phase: 'cancelled' }, OWNER);

    expect(m.jobQ.cancelJob).toHaveBeenCalledWith('a-run.1', undefined, { cascade: true });
  });
});

describe('changing a run step under the audit profile', () => {
  beforeEach(() => {
    m.state.projectProfile = 'audit';
  });

  it("allows a teammate's PATCH and records what strict would refuse", async () => {
    await route(controller(), 'update', 'a-run.1', { phase: 'done' }, TEAMMATE);

    expect(m.jobQ.updatePhase).toHaveBeenCalledWith('a-run.1', 'done');
    expect(findingsFor('jobs.run_step_change')).toEqual([
      expect.objectContaining({ project_id: 'proj_a', actor_type: 'user', actor_id: 'user_mate', detail: expect.objectContaining({ job_id: 'a-run.1' }) }),
    ]);
  });

  it("records nothing for the run's own changes, and does not cascade a cancel", async () => {
    await route(controller(), 'update', 'a-run.1', { phase: 'cancelled' }, OWNER);

    expect(findingsFor('jobs.run_step_change')).toEqual([]);
    const cascade = (m.jobQ.cancelJob.mock.calls[0] as unknown[] | undefined)?.[2] as { cascade?: boolean } | undefined;
    expect(cascade?.cascade ?? false).toBe(false);
  });
});

describe('cancelling a job with its downstream steps', () => {
  it('cancels the jobs that depend on it, transitively, when asked to', async () => {
    const { jobQueries } = await vi.importActual<typeof import('@eve/db')>('@eve/db');
    const statements: string[] = [];
    const sql = Object.assign(
      async (strings: TemplateStringsArray, ..._values: unknown[]) => {
        const text = strings.join('?');
        statements.push(text);
        if (/SELECT \* FROM jobs WHERE id/.test(text) || /RETURNING \*/.test(text)) return [{ ...m.state.jobs.get('a-run.1') }];
        if (/WITH RECURSIVE/.test(text)) return [{ id: 'a-run.2' }];
        return [];
      },
      { json: (v: unknown) => v },
    );
    const queries = jobQueries(sql as never) as unknown as {
      cancelJob(id: string, reason?: string, options?: { cascade?: boolean }): Promise<unknown>;
    };

    await queries.cancelJob('a-run.1', 'Stopped by hand', { cascade: true });
    expect(statements.some((s) => /WITH RECURSIVE downstream/.test(s))).toBe(true);

    statements.length = 0;
    await queries.cancelJob('a-run.1', 'Stopped by hand');
    expect(statements.some((s) => /WITH RECURSIVE downstream/.test(s))).toBe(false);
  });
});

describe('dependency edges of a run root', () => {
  it("refuse a teammate's edge on another person's run root under strict, and allow the run's actor", async () => {
    m.state.projectProfile = 'strict';
    const c = controller();

    await expect(route(c, 'addDependency', 'a-run', { related_job_id: 'solo-1' }, TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'removeDependency', 'a-run', 'solo-1', TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'addDependency', 'b-run', { related_job_id: 'c-run.1' }, RUN_C_STEP)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.addDependency).not.toHaveBeenCalled();

    await route(c, 'addDependency', 'a-run', { related_job_id: 'solo-1' }, OWNER);
    expect(m.jobQ.addDependency).toHaveBeenCalledWith('a-run', 'solo-1', 'blocks');
  });

  it("allow a teammate's edge on another person's run root under audit, and record it", async () => {
    m.state.projectProfile = 'audit';

    await route(controller(), 'addDependency', 'a-run', { related_job_id: 'solo-1' }, TEAMMATE);

    expect(m.jobQ.addDependency).toHaveBeenCalledWith('a-run', 'solo-1', 'blocks');
    expect(findingsFor('jobs.run_step_change')).toEqual([
      expect.objectContaining({ actor_type: 'user', actor_id: 'user_mate', detail: expect.objectContaining({ job_id: 'a-run' }) }),
    ]);
  });
});

describe("a cancel's cascade", () => {
  it("stays inside the cancelled step's own run", async () => {
    const { jobQueries } = await vi.importActual<typeof import('@eve/db')>('@eve/db');
    const calls: Array<{ text: string; values: unknown[] }> = [];
    const sql = Object.assign(
      async (strings: TemplateStringsArray, ...values: unknown[]) => {
        const text = strings.join('?');
        calls.push({ text, values });
        if (/SELECT \* FROM jobs WHERE id/.test(text) || /RETURNING \*/.test(text)) return [{ ...m.state.jobs.get('a-run.1') }];
        return [];
      },
      { json: (v: unknown) => v },
    );
    const queries = jobQueries(sql as never) as unknown as {
      cancelJob(id: string, reason?: string, options?: { cascade?: boolean }): Promise<unknown>;
    };

    await queries.cancelJob('a-run.1', 'Stopped by hand', { cascade: true });

    const downstream = calls.find((call) => /WITH RECURSIVE downstream/.test(call.text));
    expect(downstream?.text).toMatch(/step_name IS NOT NULL/);
    expect(downstream?.text).toMatch(/parent_id IS NOT DISTINCT FROM/);
    expect(downstream?.text).toMatch(/run_id IS NOT DISTINCT FROM/);
    expect(downstream?.values).toContain('a-run');
  });
});

