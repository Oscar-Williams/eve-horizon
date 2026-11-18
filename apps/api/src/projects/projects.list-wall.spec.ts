import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ProjectsService } from './projects.service.js';
import { SecurityService } from '../security/security.service.js';
import { accessStore as store } from '../../test/unit/helpers/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('../../test/unit/helpers/access-store.js');
  return { ...actual, ...accessStore.queries };
});

const ORG = 'org_a';

async function listed(userId: string): Promise<string[]> {
  const service = new ProjectsService(store.db as never, {} as never, {} as never, new SecurityService(store.db as never));
  const result = await service.list({ limit: 100, offset: 0, include_deleted: false, user_id: userId });
  return result.data.map((project) => project.id).sort();
}

function seed(profile: 'legacy' | 'audit' | 'strict' | null) {
  store.reset();
  store.addOrg(ORG, 'acme');
  store.addProject('proj_mine', ORG, 'mine', profile);
  store.addProject('proj_other', ORG, 'other', profile);
  store.joinOrg('user_member', ORG, 'member');
  store.joinProject('user_member', 'proj_mine', 'member');
  store.joinOrg('user_admin', ORG, 'admin');
}

describe('project listing (P1-5)', () => {
  beforeEach(() => vi.clearAllMocks());

  it('leaves out a project an org member reaches only through the org member role, when strict comes from the instance', async () => {
    seed(null);
    store.setInstanceProfile('strict');

    await expect(listed('user_member')).resolves.toEqual(['proj_mine']);
    await expect(listed('user_admin')).resolves.toEqual(['proj_mine', 'proj_other']);
  });

  it('lists the project under audit and records the grant', async () => {
    seed('audit');

    await expect(listed('user_member')).resolves.toEqual(['proj_mine', 'proj_other']);
    expect(store.findings('access.implicit_project').map((f) => f.project_id)).toEqual(['proj_other']);
  });

  it('changes nothing under legacy', async () => {
    seed('legacy');

    await expect(listed('user_member')).resolves.toEqual(['proj_mine', 'proj_other']);
    expect(store.findings()).toEqual([]);
  });
});
