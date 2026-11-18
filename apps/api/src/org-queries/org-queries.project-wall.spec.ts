import { beforeEach, describe, expect, it, vi } from 'vitest';
import { OrgQueriesService } from './org-queries.service.js';
import { SecurityService } from '../security/security.service.js';
import { accessStore as store } from '../../test/unit/helpers/access-store.js';

const across = vi.hoisted(() => ({
  findJobsAcrossProjects: vi.fn(async (_projectIds: string[]) => ({ items: [], next_cursor: null })),
  jobStats: vi.fn(async (_projectIds: string[]) => ({ total: 0, byPhase: [], byProject: [] })),
  findEventsAcrossProjects: vi.fn(async (_projectIds: string[]) => ({ items: [], next_cursor: null })),
  findAgentsAcrossProjects: vi.fn(async (_projectIds: string[]) => []),
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('../../test/unit/helpers/access-store.js');
  return {
    ...actual,
    ...accessStore.queries,
    orgQueryQueries: () => ({ ...accessStore.queries.orgQueryQueries(), ...across }),
  };
});

const ORG = 'org_a';

function service() {
  return new OrgQueriesService(store.db as never, new SecurityService(store.db as never));
}

/** The project ids each org-wide query was asked to span. */
async function spanned(userId: string): Promise<string[][]> {
  const svc = service();
  await svc.findJobs(ORG, {}, userId);
  await svc.jobStats(ORG, userId);
  await svc.findEvents(ORG, {}, userId);
  await svc.findAgents(ORG, userId);
  return [
    across.findJobsAcrossProjects.mock.calls.at(-1)![0],
    across.jobStats.mock.calls.at(-1)![0],
    across.findEventsAcrossProjects.mock.calls.at(-1)![0],
    across.findAgentsAcrossProjects.mock.calls.at(-1)![0],
  ].map((ids) => [...ids].sort());
}

function seed(profile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme');
  store.addProject('proj_mine', ORG, 'mine', profile);
  store.addProject('proj_other', ORG, 'other', profile);
  store.joinOrg('user_member', ORG, 'member');
  store.joinProject('user_member', 'proj_mine', 'member');
  store.joinOrg('user_admin', ORG, 'admin');
}

describe('org-wide queries span only the projects the caller may see (P1-5)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('leave out a strict project an org member reaches only through the org member role', async () => {
    seed('strict');

    for (const ids of await spanned('user_member')) {
      expect(ids).toEqual(['proj_mine']);
    }
    expect(store.findings('access.implicit_project')[0]).toMatchObject({ project_id: 'proj_other', profile: 'strict' });
  });

  it('leave org admins every project', async () => {
    seed('strict');

    for (const ids of await spanned('user_admin')) {
      expect(ids).toEqual(['proj_mine', 'proj_other']);
    }
    expect(store.findings()).toEqual([]);
  });

  it('keep the project under audit and record the grant', async () => {
    seed('audit');

    for (const ids of await spanned('user_member')) {
      expect(ids).toEqual(['proj_mine', 'proj_other']);
    }
    expect(store.findings('access.implicit_project').map((f) => f.project_id)).toEqual(['proj_other']);
  });

  it('change nothing under legacy', async () => {
    seed('legacy');

    for (const ids of await spanned('user_member')) {
      expect(ids).toEqual(['proj_mine', 'proj_other']);
    }
    expect(store.findings()).toEqual([]);
  });
});
