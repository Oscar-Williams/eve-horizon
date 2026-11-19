import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NotFoundException } from '@nestjs/common';
import { OrgsService } from './orgs.service.js';
import { accessStore as store } from '../auth/__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('../auth/__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

const ORG = 'org_a';
const OTHER_ORG = 'org_b';

function service() {
  return new OrgsService(store.db as never, {} as never, {} as never);
}

describe('removing an org member (P1-5, always on)', () => {
  beforeEach(() => {
    store.reset();
    store.addOrg(ORG, 'acme');
    store.addOrg(OTHER_ORG, 'other');
    store.addProject('proj_a', ORG, 'alpha');
    store.addProject('proj_b', OTHER_ORG, 'beta');
    store.joinOrg('user_owner', ORG, 'owner');
    store.joinOrg('user_gone', ORG, 'member');
    store.joinOrg('user_gone', OTHER_ORG, 'member');
    store.joinProject('user_gone', 'proj_a', 'admin');
    store.joinProject('user_gone', 'proj_b', 'member');
    store.bind({ org_id: ORG, principal_id: 'user_gone', project_id: 'proj_a', permissions: ['secrets:read'] });
    store.bind({ org_id: ORG, principal_id: 'user_gone', permissions: ['orgfs:read'], scope_json: { orgfs: { allow_prefixes: ['/shared'] } } });
    store.bind({ org_id: OTHER_ORG, principal_id: 'user_gone', permissions: ['jobs:read'] });
    store.addToGroup('grp_ops', ORG, 'user_gone');
    store.addToGroup('grp_ops_b', OTHER_ORG, 'user_gone');
  });

  it("also removes the person's project memberships, bindings and group memberships in that org", async () => {
    await service().removeMember(ORG, 'user_gone');

    expect(store.state.orgMemberships.filter((m) => m.user_id === 'user_gone').map((m) => m.org_id)).toEqual([OTHER_ORG]);
    expect(store.state.projectMemberships.filter((m) => m.user_id === 'user_gone').map((m) => m.project_id)).toEqual(['proj_b']);
    expect(store.state.bindings.filter((b) => b.principal_id === 'user_gone').map((b) => b.org_id)).toEqual([OTHER_ORG]);
    expect(store.state.groupMembers.filter((m) => m.principal_id === 'user_gone').map((m) => m.group_id)).toEqual(['grp_ops_b']);
  });

  it('removes nothing for someone who is not a member of the org', async () => {
    store.joinProject('user_guest', 'proj_a', 'member');

    await expect(service().removeMember(ORG, 'user_guest')).rejects.toBeInstanceOf(NotFoundException);
    expect(store.state.projectMemberships.some((m) => m.user_id === 'user_guest')).toBe(true);
  });
});
