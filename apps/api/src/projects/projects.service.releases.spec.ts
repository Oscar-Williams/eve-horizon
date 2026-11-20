import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ConflictException, NotFoundException } from '@nestjs/common';
import { ProjectsService } from './projects.service';

/**
 * A release an environment runs (its current or last applied release) cannot
 * be deleted: the API answers 409 naming the environments. The database
 * stand-in below refuses the delete as the query does.
 */
const mocks = vi.hoisted(() => {
  const inUse: Record<string, string[]> = {};
  const releases = {
    findByProjectAndTag: vi.fn(),
    delete: vi.fn(async (id: string) => !(inUse[id]?.length)),
    listEnvironmentsUsing: vi.fn(async (id: string) => inUse[id] ?? []),
    deleteByProjectOlderThan: vi.fn(async () => 2),
  };
  return { inUse, releases, projects: { findById: vi.fn() } };
});

vi.mock('@eve/db', () => ({
  projectQueries: vi.fn(() => mocks.projects),
  orgQueries: vi.fn(() => ({})),
  membershipQueries: vi.fn(() => ({})),
  userQueries: vi.fn(() => ({})),
  releaseQueries: vi.fn(() => mocks.releases),
  agentConfigQueries: vi.fn(() => ({})),
  agentQueries: vi.fn(() => ({})),
  teamQueries: vi.fn(() => ({})),
  threadQueries: vi.fn(() => ({})),
  scheduleQueries: vi.fn(() => ({})),
  spendQueries: vi.fn(() => ({})),
  environmentQueries: vi.fn(() => ({})),
  managedDbQueries: vi.fn(() => ({})),
}));

describe('ProjectsService.deleteRelease', () => {
  let service: ProjectsService;

  beforeEach(() => {
    vi.clearAllMocks();
    for (const key of Object.keys(mocks.inUse)) delete mocks.inUse[key];
    mocks.projects.findById.mockResolvedValue({ id: 'proj_shop', org_id: 'org_acme' });
    mocks.releases.findByProjectAndTag.mockImplementation(async (_project: string, tag: string) =>
      (tag === 'v1' ? { id: 'rel_1', project_id: 'proj_shop', tag } : null));
    service = new ProjectsService({} as never, {} as never, {} as never);
  });

  it('refuses with 409, naming the environments, a release an environment runs', async () => {
    mocks.inUse.rel_1 = ['prod', 'staging'];

    const refused = service.deleteRelease('proj_shop', 'v1');

    await expect(refused).rejects.toBeInstanceOf(ConflictException);
    await expect(refused).rejects.toThrow(/prod, staging/);
  });

  it('deletes a release no environment runs', async () => {
    await expect(service.deleteRelease('proj_shop', 'v1')).resolves.toBeUndefined();
    expect(mocks.releases.delete).toHaveBeenCalledWith('rel_1');
  });

  it('answers 404 for a tag the project does not have', async () => {
    await expect(service.deleteRelease('proj_shop', 'v9')).rejects.toBeInstanceOf(NotFoundException);
  });
});
