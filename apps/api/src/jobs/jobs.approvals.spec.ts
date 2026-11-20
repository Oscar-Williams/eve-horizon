import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, ForbiddenException } from '@nestjs/common';
import { ReviewDecidedError } from '@eve/db';
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
      job('a-run.3', { parent_id: 'a-run', depth: 1, step_name: 'sign-off', phase: 'active', review_required: 'human', review_status: null }),
      job('solo-h', { phase: 'active', review_required: 'human', review_status: null }),
    ];
    return new Map(rows.map((row) => [row.id, row]));
  }

  const state = {
    jobs: seed(),
    projectProfile: null as string | null,
    findings: [] as Array<Record<string, unknown>>,
    /** True while a transaction body runs. */
    inTransaction: false,
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

/** Answers the run-root probe and the actor lock; every other raw query returns nothing. */
const db = Object.assign(
  async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?');
    if (/FOR UPDATE/.test(sql)) {
      const row = m.state.jobs.get(values[0] as string);
      return row ? [{ ...row }] : [];
    }
    if (/WHERE parent_id = \?/.test(sql) && /step_name IS NOT NULL/.test(sql)) {
      return [...m.state.jobs.values()].filter((row) => row.parent_id === values[0] && row.step_name).map((row) => ({ id: row.id }));
    }
    return [];
  },
  { json: (v: unknown) => v },
);
Object.assign(db, {
  begin: async <T>(work: (tx: unknown) => Promise<T>) => {
    m.state.inTransaction = true;
    try {
      return await work(db);
    } finally {
      m.state.inTransaction = false;
    }
  },
});

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

describe('the decider of a PATCH that approves a review', () => {
  it('is the caller, recorded as approve records it, on every profile', async () => {
    await route(controller(), 'update', 'solo-r', { phase: 'done' }, TEAMMATE);

    expect(m.jobQ.approveReview).toHaveBeenCalledWith('solo-r', 'user_mate', undefined, 'user');
    expect(m.jobQ.updatePhase).not.toHaveBeenCalled();
  });

  it('is recorded as the job for a job token under audit', async () => {
    m.state.projectProfile = 'audit';

    await route(controller(), 'update', 'solo-r', { phase: 'done' }, OWNER_AGENT);

    expect(m.jobQ.approveReview).toHaveBeenCalledWith('solo-r', 'job:solo-1', undefined, 'agent');
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

    expect(m.jobQ.approveReview).toHaveBeenCalledWith('solo-r', 'user_mate', undefined, 'user');
  });
});

describe('changes that settle or remove a review, under the strict profile', () => {
  beforeEach(() => {
    m.state.projectProfile = 'strict';
  });

  it("refuse a job token lowering review_required before review, on its own job or another's", async () => {
    const c = controller();
    await expect(route(c, 'update', 'solo-h', { review_required: 'none' }, jobToken('solo-h'))).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'update', 'solo-h', { review_required: 'agent' }, OWNER_AGENT)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("refuse a run step's token lowering review_required on its own step or another step of the run", async () => {
    const c = controller();
    await expect(route(c, 'update', 'a-run.3', { review_required: 'none' }, jobToken('a-run.3'))).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'update', 'a-run.3', { review_required: 'none' }, jobToken('a-run.2'))).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('refuse a job token sending a job in review back to active, or cancelling it', async () => {
    const c = controller();
    await expect(route(c, 'update', 'solo-r', { phase: 'active' }, OWNER_AGENT)).rejects.toBeInstanceOf(ForbiddenException);
    await expect(route(c, 'update', 'solo-r', { phase: 'cancelled' }, OWNER_AGENT)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobQ.updatePhase).not.toHaveBeenCalled();
  });

  it("accept a person's own token lowering review_required, and a job token raising it", async () => {
    const c = controller();
    await expect(route(c, 'update', 'solo-h', { review_required: 'none' }, OWNER)).resolves.toBeDefined();
    await expect(route(c, 'update', 'solo-1', { review_required: 'human' }, OWNER_AGENT)).resolves.toBeDefined();
  });
});

describe('changes that settle or remove a review, under the audit profile', () => {
  beforeEach(() => {
    m.state.projectProfile = 'audit';
  });

  it("allow a run step's token lowering review_required and record it under both rules", async () => {
    await expect(route(controller(), 'update', 'a-run.3', { review_required: 'none' }, jobToken('a-run.2'))).resolves.toBeDefined();

    expect(findingsFor('jobs.approve_token')).toEqual([
      expect.objectContaining({ actor_type: 'job', actor_id: 'a-run.2', detail: expect.objectContaining({ job_id: 'a-run.3' }) }),
    ]);
    expect(findingsFor('jobs.run_step_change')).toEqual([
      expect.objectContaining({ actor_type: 'job', actor_id: 'a-run.2', detail: expect.objectContaining({ job_id: 'a-run.3' }) }),
    ]);
  });

  it('allow a job token sending a job in review back to active, and record it', async () => {
    await expect(route(controller(), 'update', 'solo-r', { phase: 'active' }, OWNER_AGENT)).resolves.toBeDefined();

    expect(findingsFor('jobs.approve_token')).toEqual([
      expect.objectContaining({ actor_type: 'job', actor_id: 'solo-1', detail: expect.objectContaining({ job_id: 'solo-r', action: 'reject' }) }),
    ]);
  });
});

describe('a PATCH decided on a job that changed before it was applied', () => {
  /** The job as the PATCH first read it, while the stored row has since moved on. */
  function readAs(jobId: string, snapshot: Record<string, unknown>) {
    const row = m.state.jobs.get(jobId)!;
    m.jobQ.findById.mockImplementationOnce(async () => ({ ...row, ...snapshot }));
  }

  beforeEach(() => {
    m.state.projectProfile = 'strict';
  });

  it('is refused with 409 when the job went into review after it was read', async () => {
    m.state.jobs.get('solo-h')!.phase = 'review';
    readAs('solo-h', { phase: 'active' });

    await expect(route(controller(), 'update', 'solo-h', { phase: 'done' }, jobToken('solo-h'))).rejects.toBeInstanceOf(ConflictException);
    expect(m.jobQ.updatePhase).not.toHaveBeenCalled();
    expect(m.jobQ.approveReview).not.toHaveBeenCalled();
  });

  it('is refused with 409 when the review it needs was raised after it was read', async () => {
    readAs('solo-h', { review_required: 'none' });

    await expect(route(controller(), 'update', 'solo-h', { review_required: 'none', priority: 1 }, jobToken('solo-h')))
      .rejects.toBeInstanceOf(ConflictException);
  });
});

describe('a PATCH that sends a job in review back to active', () => {
  it('is a rejection: it records the caller as the decider and starts a new attempt, as reject does', async () => {
    await route(controller(), 'update', 'solo-r', { phase: 'active' }, OWNER);

    expect(m.jobQ.rejectReview).toHaveBeenCalledWith('solo-r', 'user_owner', expect.any(String), 'user');
    expect(m.jobQ.updatePhase).not.toHaveBeenCalled();
  });
});


describe('a review decision', () => {
  /** The decisions as the database makes them: once, then ReviewDecidedError. */
  function decideOnce() {
    const decide = (status: 'approved' | 'rejected', phase: string) => async (id: string, reviewer?: string) => {
      const row = m.state.jobs.get(id)!;
      if (row.phase !== 'review') throw new ReviewDecidedError(id, String(row.review_status));
      Object.assign(row, { phase, review_status: status, reviewer });
      return { ...row };
    };
    m.jobQ.approveReview.mockImplementation(decide('approved', 'done'));
    m.jobQ.rejectReview.mockImplementation(decide('rejected', 'active'));
  }

  beforeEach(decideOnce);

  it('is made once: a reject after an approve gets 409 and the job stays done', async () => {
    const c = controller();
    await route(c, 'approve', 'solo-r', {}, OWNER);

    await expect(route(c, 'reject', 'solo-r', { reason: 'again' }, TEAMMATE)).rejects.toBeInstanceOf(ConflictException);
    expect(m.state.jobs.get('solo-r')).toMatchObject({ phase: 'done', review_status: 'approved', reviewer: 'user_owner' });
  });

  it('is made once: an approve after a reject gets 409', async () => {
    const c = controller();
    await route(c, 'reject', 'solo-r', { reason: 'again' }, OWNER);

    await expect(route(c, 'approve', 'solo-r', {}, TEAMMATE)).rejects.toBeInstanceOf(ConflictException);
    expect(m.state.jobs.get('solo-r')).toMatchObject({ phase: 'active', review_status: 'rejected', reviewer: 'user_owner' });
  });

  it('is made once: a second approve gets 409 and keeps the first reviewer', async () => {
    const c = controller();
    await route(c, 'approve', 'solo-r', {}, OWNER);

    await expect(route(c, 'approve', 'solo-r', {}, TEAMMATE)).rejects.toBeInstanceOf(ConflictException);
    expect(m.state.jobs.get('solo-r')).toMatchObject({ reviewer: 'user_owner' });
  });

  it('is made in a transaction, on the approve route as on reject', async () => {
    const seen: boolean[] = [];
    m.jobQ.approveReview.mockImplementation(async (id: string) => {
      seen.push(m.state.inTransaction);
      return { ...m.state.jobs.get(id)!, phase: 'done' };
    });

    await route(controller(), 'approve', 'solo-r', {}, OWNER);

    expect(seen).toEqual([true]);
  });
});
