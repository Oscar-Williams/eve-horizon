import { beforeEach, describe, expect, it, vi } from 'vitest';
import { JobsService } from './jobs.service';
import { AccessService } from '../auth/access.service';
import type { AuthUser } from '../auth/auth.types';

const m = vi.hoisted(() => ({
  job: null as Record<string, unknown> | null,
  jobQ: {
    findById: vi.fn(),
    rejectReview: vi.fn(),
  },
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  jobQueries: vi.fn(() => m.jobQ),
}));

type Statement = { sql: string; values: unknown[] };
const statements: Statement[] = [];
const recorder = Object.assign(
  async (strings: TemplateStringsArray, ...values: unknown[]) => {
    statements.push({ sql: strings.join('?'), values });
    return [];
  },
  { json: (v: unknown) => v },
);
const fakeDb = Object.assign(recorder, { begin: async <T>(work: (tx: unknown) => Promise<T>) => work(recorder) });

function service(): JobsService {
  return new JobsService(fakeDb as never, {} as never, {} as never, {} as never, new AccessService({} as never, fakeDb as never));
}

const RESTRICTED: AuthUser = {
  user_id: 'user_owner', is_job_token: true, job_id: 'opps-1', project_id: 'proj_a',
  permissions: ['jobs:write'], secrets_allowlist: ['ANTHROPIC_API_KEY', 'OPPS_SIGNING_KEY'],
} as AuthUser;

function allowlistWrites(): unknown[] {
  return statements.filter((s) => /UPDATE jobs SET secrets_allowlist = \?/.test(s.sql)).map((s) => s.values[0]);
}

beforeEach(() => {
  vi.clearAllMocks();
  statements.length = 0;
  m.job = { id: 'a-1', project_id: 'proj_a', phase: 'review', secrets_allowlist: null, created_at: new Date(), updated_at: new Date() };
  m.jobQ.findById.mockImplementation(async () => (m.job ? { ...m.job } : null));
  m.jobQ.rejectReview.mockImplementation(async () => ({ ...m.job, phase: 'active', created_at: new Date(), updated_at: new Date() }));
});

describe('POST /jobs/:job_id/reject, which runs the job again', () => {
  it("narrows the job to a restricted rejecter's allowlist", async () => {
    await service().reject('a-1', { reviewer_id: 'opps-1', reason: 'redo' } as never, RESTRICTED);

    expect(m.jobQ.rejectReview).toHaveBeenCalled();
    expect(allowlistWrites()).toEqual([['ANTHROPIC_API_KEY', 'OPPS_SIGNING_KEY']]);
  });

  it('leaves the job as it is for an unrestricted rejecter', async () => {
    await service().reject('a-1', { reviewer_id: 'user_owner', reason: 'redo' } as never, { user_id: 'user_owner' } as AuthUser);

    expect(allowlistWrites()).toEqual([]);
  });
});
