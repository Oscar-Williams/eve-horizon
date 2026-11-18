import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { JobsService } from './jobs.service';
import { JobsController } from './jobs.controller';
import { AccessService } from '../auth/access.service';
import { SecurityService } from '../security/security.service';
import type { AuthUser } from '../auth/auth.types';

/**
 * Jobs awaiting review in proj_a: solo-r, a job of user_owner's outside any
 * run, and a-run.1, a step of user_owner's workflow run a-run.
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
      phase: 'review',
      priority: 2,
      assignee: null,
      review_required: 'human',
      review_status: 'pending',
      reviewer: null,
      defer_until: null,
      due_at: null,
      ready_at: null,
      closed_at: null,
      close_reason: null,
      hints: {},
      token_scope: null,
      token_permissions: null,
      secrets_allowlist: null,
      user_secrets_excluded: false,
      run_id: null,
      step_name: null,
      execution_type: 'agent',
      execution_mode: 'ephemeral',
      actor_user_id: 'user_owner',
      created_at: now,
      updated_at: now,
      ...overrides,
    };
  }

  function seed(): Map<string, Row> {
    const rows = [
      job('solo-r'),
      job('solo-1', { phase: 'active', review_required: 'none', review_status: null }),
      job('a-run', { phase: 'active', review_required: 'none', review_status: null, hints: { workflow_root: true } }),
      job('a-run.1', { parent_id: 'a-run', depth: 1, step_name: 'draft' }),
      job('a-run.2', { parent_id: 'a-run', depth: 1, step_name: 'publish', phase: 'active', review_required: 'none', review_status: null }),
    ];
    return new Map(rows.map((row) => [row.id, row]));
  }

  const state = {
    jobs: seed(),
    projectProfile: null as string | null,
    findings: [] as Array<Record<string, unknown>>,
  };
  const setPhase = (id: string, phase: string) => {
    const row = state.jobs.get(id);
    if (row) row.phase = phase;
    return row ? { ...row } : null;
  };

  const jobQ = {
    findById: vi.fn(async (id: string) => {
      const row = state.jobs.get(id);
      return row ? { ...row } : null;
    }),
    updatePhase: vi.fn(async (id: string, phase: string) => ({ success: true, job: setPhase(id, phase) })),
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
    systemSettingsQueries: vi.fn(() => ({ get: vi.fn(async () => null) })),
    securityQueries: vi.fn(() => ({
      getProfiles: vi.fn(async () => ({ org_id: 'org_a', org_profile: null, project_profile: m.state.projectProfile })),
      recordFinding: vi.fn(async (finding: Record<string, unknown>) => {
        m.state.findings.push(finding);
      }),
    })),
  };
});

/** Answers the run-root probe; every other raw query returns nothing. */
const db = Object.assign(
  async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?');
    if (/WHERE parent_id = \?/.test(sql) && /step_name IS NOT NULL/.test(sql)) {
      return [...m.state.jobs.values()].filter((row) => row.parent_id === values[0] && row.step_name).map((row) => ({ id: row.id }));
    }
    return [];
  },
  { json: (v: unknown) => v },
);
Object.assign(db, { begin: async <T>(work: (tx: unknown) => Promise<T>) => work(db) });

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
  return new JobsController(new Service(db, {} as never, {} as never, {} as never, access, new SecurityService({} as never), rbac), rbac as never);
}

/** Calls a route with the arguments Nest passes it. */
function route<T = unknown>(target: JobsController, method: keyof JobsController, ...args: unknown[]): Promise<T> {
  return (target[method] as unknown as (...a: unknown[]) => Promise<T>).apply(target, args);
}

const OWNER: AuthUser = { user_id: 'user_owner' };
const TEAMMATE: AuthUser = { user_id: 'user_mate' };
const ADMIN: AuthUser = { user_id: 'user_admin' };

function jobToken(jobId: string): AuthUser {
  return {
    user_id: 'user_owner',
    is_job_token: true,
    job_id: jobId,
    org_id: 'org_a',
    project_id: 'proj_a',
    permissions: ['jobs:read', 'jobs:write'],
  };
}

/** An agent job of user_owner's: its token carries user_owner's id. */
const OWNER_AGENT = jobToken('solo-1');
/** A deployed service of the project. */
const SERVICE: AuthUser = {
  user_id: 'svc:proj_a:prod:web',
  is_service_token: true,
  service_name: 'web',
  org_id: 'org_a',
  project_id: 'proj_a',
  permissions: ['jobs:read', 'jobs:write'],
};

function findingsFor(rule: string) {
  return m.state.findings.filter((f) => f.rule === rule);
}

beforeEach(() => {
  vi.clearAllMocks();
  m.state.jobs = m.seed();
  m.state.projectProfile = null;
  m.state.findings = [];
});

describe('the decider of a job review', () => {
  it('is the caller, whatever reviewer_id the body names', async () => {
    await route(controller(), 'approve', 'solo-r', { reviewer_id: 'someone-else', comment: 'ok' }, OWNER);

    expect(m.jobQ.approveReview).toHaveBeenCalledWith('solo-r', 'user_owner', 'ok', 'user');
  });

  it('is the caller on a rejection too', async () => {
    await route(controller(), 'reject', 'solo-r', { reviewer_id: 'someone-else', reason: 'again' }, TEAMMATE);

    expect(m.jobQ.rejectReview).toHaveBeenCalledWith('solo-r', 'user_mate', 'again', 'user');
  });

  it("is recorded as the job for a job token, never as the person it runs as, and audit records it", async () => {
    m.state.projectProfile = 'audit';

    await route(controller(), 'approve', 'solo-r', {}, OWNER_AGENT);

    expect(m.jobQ.approveReview).toHaveBeenCalledWith('solo-r', 'job:solo-1', undefined, 'agent');
    expect(findingsFor('jobs.approve_token')).toEqual([
      expect.objectContaining({ actor_type: 'job', actor_id: 'solo-1', detail: expect.objectContaining({ job_id: 'solo-r' }) }),
    ]);
  });

  it("records nothing under audit for a person's own approval", async () => {
    m.state.projectProfile = 'audit';

    await route(controller(), 'approve', 'solo-r', {}, TEAMMATE);

    expect(m.state.findings).toEqual([]);
  });
});

describe('job approvals under the strict profile', () => {
  beforeEach(() => {
    m.state.projectProfile = 'strict';
  });

  it('refuse a job token or a service token, and change nothing', async () => {
    const c = controller();
    await expect(route(c, 'approve', 'solo-r', {}, OWNER_AGENT)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'reject', 'solo-r', { reason: 'again' }, OWNER_AGENT)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'approve', 'solo-r', {}, SERVICE)).rejects.toBeInstanceOf(ForbiddenException);

    expect(m.jobQ.approveReview).not.toHaveBeenCalled();
    expect(m.jobQ.rejectReview).not.toHaveBeenCalled();
  });

  it("accept any member's own token on a job outside a run", async () => {
    await route(controller(), 'approve', 'solo-r', {}, TEAMMATE);

    expect(m.jobQ.approveReview).toHaveBeenCalledWith('solo-r', 'user_mate', undefined, 'user');
  });

  it("refuse a step of the run approving another of the run's steps", async () => {
    await expect(route(controller(), 'approve', 'a-run.1', {}, jobToken('a-run.2'))).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.approveReview).not.toHaveBeenCalled();
  });

  it("accept only the run's actor or a project admin on a run step", async () => {
    await expect(route(controller(), 'approve', 'a-run.1', {}, TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);

    await route(controller(), 'approve', 'a-run.1', {}, OWNER);
    m.state.jobs = m.seed();
    await route(controller(), 'approve', 'a-run.1', {}, ADMIN);

    expect(m.jobQ.approveReview).toHaveBeenCalledTimes(2);
  });

  it("count a job token's PATCH from review to done, or of review_required in review, as an approval", async () => {
    const c = controller();
    await expect(route(c, 'update', 'solo-r', { phase: 'done' }, OWNER_AGENT)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'update', 'solo-r', { review_required: 'none' }, OWNER_AGENT)).rejects.toBeInstanceOf(ForbiddenException);

    expect(m.jobQ.updatePhase).not.toHaveBeenCalled();
    // One finding row per rule, actor and day: the second refusal adds none.
    expect(findingsFor('jobs.approve_token')).toHaveLength(1);
  });

  it("refuse a non-actor member's PATCH of a run step from review to done", async () => {
    await expect(route(controller(), 'update', 'a-run.1', { phase: 'done' }, TEAMMATE)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.updatePhase).not.toHaveBeenCalled();
  });

  it("leave a member's own PATCH from review to done on a job outside a run", async () => {
    await route(controller(), 'update', 'solo-r', { phase: 'done' }, TEAMMATE);

    expect(m.jobQ.updatePhase).toHaveBeenCalledWith('solo-r', 'done');
  });
});
