import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { ManagedDbSnapshotController } from './managed-db-snapshot.controller.js';
import { RbacService } from '../auth/rbac.service.js';
import { SecurityService } from '../security/security.service.js';
import type { AuthUser } from '../auth/auth.types.js';
import { accessStore as store } from '../auth/__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('../auth/__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

const ORG = 'org_acme';
const PROJECT = 'proj_shop';
const member: AuthUser = { user_id: 'user_alice' };
const admin: AuthUser = { user_id: 'user_bob' };

function controller() {
  const snapshots = { getDownloadUrl: vi.fn(async () => ({ url: 'https://storage.eve.example/snap', expires_in: 3600 })) };
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  return { snapshots, controller: new ManagedDbSnapshotController(snapshots as never, rbac) };
}

function seed(profile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme');
  store.addProject(PROJECT, ORG, 'shop', profile, profile === 'strict' ? 2 : null);
  store.joinOrg(member.user_id, ORG, 'member');
  store.joinProject(member.user_id, PROJECT, 'member');
  store.joinOrg(admin.user_id, ORG, 'admin');
}

describe('snapshot download needs envdb:export (rule envdb.export, P2-7)', () => {
  it('under strict, refuses a member who holds only envdb:read before a URL is signed', async () => {
    seed('strict');
    const { controller: c, snapshots } = controller();
    await expect(c.downloadSnapshot(PROJECT, 'prod', 'snap_1', member)).rejects.toBeInstanceOf(ForbiddenException);
    expect(snapshots.getDownloadUrl).not.toHaveBeenCalled();
    expect(store.findings('envdb.export')[0]).toMatchObject({ profile: 'strict', project_id: PROJECT, actor_id: member.user_id });
  });

  it('under strict, signs the URL for an admin', async () => {
    seed('strict');
    const { controller: c, snapshots } = controller();
    await expect(c.downloadSnapshot(PROJECT, 'prod', 'snap_1', admin)).resolves.toMatchObject({ url: expect.any(String) });
    expect(snapshots.getDownloadUrl).toHaveBeenCalledWith(PROJECT, 'prod', 'snap_1');
  });

  it('under audit, signs the URL for a member and records the use of envdb:read as envdb:export', async () => {
    seed('audit');
    const { controller: c, snapshots } = controller();
    await expect(c.downloadSnapshot(PROJECT, 'prod', 'snap_1', member)).resolves.toMatchObject({ url: expect.any(String) });
    expect(snapshots.getDownloadUrl).toHaveBeenCalled();
    expect(store.findings('access.operator_rights')[0]?.detail).toMatchObject({ permission: 'envdb:export', implied_by: 'envdb:read' });
  });

  it('under legacy, signs the URL for a member and records nothing', async () => {
    seed('legacy');
    const { controller: c } = controller();
    await expect(c.downloadSnapshot(PROJECT, 'prod', 'snap_1', member)).resolves.toMatchObject({ url: expect.any(String) });
    expect(store.findings()).toEqual([]);
  });
});
