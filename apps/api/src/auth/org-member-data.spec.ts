import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException } from '@nestjs/common';
import { RbacService } from './rbac.service.js';
import { AccessService } from './access.service.js';
import { ScopedAccessService } from './scoped-access.service.js';
import { SecurityService } from '../security/security.service.js';
import { CloudFsController } from '../cloud-fs/cloud-fs.controller.js';
import type { AuthUser } from './auth.types.js';
import { accessStore as store } from './__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('./__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

/**
 * Under an org's strict profile the org member role carries no wildcard over
 * org files, docs or cloud-fs: members reach org data only through bindings.
 * Org owners and admins keep theirs (P1-6).
 */
const ORG = 'org_a';
const PROJECT = 'proj_a';
const member: AuthUser = { user_id: 'user_member' };
const reader: AuthUser = { user_id: 'user_reader' };
const orgAdmin: AuthUser = { user_id: 'user_admin' };
const owner: AuthUser = { user_id: 'user_owner' };

function services() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  const scoped = new ScopedAccessService({ isEnabled: () => true } as never, access, rbac, security);
  const cloudFs = {
    listMounts: vi.fn(async () => [{ id: 'cfm_1', org_id: ORG, project_id: null }, { id: 'cfm_2', org_id: ORG, project_id: null }]),
    browse: vi.fn(async (_org: string, mountId?: string) => ({ mount_id: mountId ?? 'cfm_1', path: '/', entries: [] })),
    search: vi.fn(async (_org: string, mountId?: string) => ({ mount_id: mountId ?? 'cfm_1', entries: [] })),
  };
  return { access, cloudFs, controller: new CloudFsController(cloudFs as never, scoped) };
}

function seed(orgProfile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme', orgProfile);
  store.addProject(PROJECT, ORG, 'deals');
  store.joinOrg(member.user_id, ORG, 'member');
  store.joinProject(member.user_id, PROJECT, 'member');
  store.joinOrg(reader.user_id, ORG, 'member');
  store.bind({
    org_id: ORG, principal_id: reader.user_id, permissions: ['cloud_fs:read'],
    scope_json: { cloud_fs: { allow_mount_ids: ['cfm_1'] } },
  });
  store.joinOrg(orgAdmin.user_id, ORG, 'admin');
  store.joinOrg(owner.user_id, ORG, 'owner');
}

const mountRead = (id: string) => ({ type: 'cloud_fs' as const, id, action: 'read' as const });

describe('the org member role and org data (P1-6)', () => {
  beforeEach(() => vi.clearAllMocks());

  describe('under a strict org', () => {
    beforeEach(() => seed('strict'));

    it('gives the member role no cloud-fs mount', async () => {
      const { access } = services();
      const can = (user: AuthUser, mount: string) =>
        access.can({ org_id: ORG, principal_type: 'user', principal_id: user.user_id, permission: 'cloud_fs:read', resource: mountRead(mount) });

      await expect(can(member, 'cfm_1')).resolves.toMatchObject({ allowed: false });
      await expect(can(reader, 'cfm_1')).resolves.toMatchObject({ allowed: true });
      await expect(can(reader, 'cfm_2')).resolves.toMatchObject({ allowed: false });
      await expect(can(orgAdmin, 'cfm_2')).resolves.toMatchObject({ allowed: true });
      await expect(can(owner, 'cfm_2')).resolves.toMatchObject({ allowed: true });
      expect(store.findings('access.org_data_role_wildcard')[0]).toMatchObject({ profile: 'strict', actor_id: member.user_id });
    });

    it('leaves a member their project\'s env-db', async () => {
      const { access } = services();

      await expect(access.can({
        org_id: ORG, principal_type: 'user', principal_id: member.user_id, project_id: PROJECT,
        permission: 'envdb:read', resource: { type: 'envdb', id: 'public.deals', action: 'read' },
      })).resolves.toMatchObject({ allowed: true });
    });

    it('holds a person\'s default-mount reads and mount listing to the mounts they may read', async () => {
      const { controller, cloudFs } = services();

      await expect(controller.browse(ORG, member, {})).rejects.toBeInstanceOf(HttpException);
      await expect(controller.search(ORG, member, { q: 'deal' })).rejects.toBeInstanceOf(HttpException);
      expect(cloudFs.browse).not.toHaveBeenCalled();
      await expect(controller.listMounts(ORG, member)).resolves.toEqual({ mounts: [] });
      await expect(controller.listMounts(ORG, reader)).resolves.toMatchObject({ mounts: [{ id: 'cfm_1' }] });
      await expect(controller.browse(ORG, reader, {})).resolves.toMatchObject({ mount_id: 'cfm_1' });
      await expect(controller.listMounts(ORG, orgAdmin)).resolves.toMatchObject({ mounts: [{ id: 'cfm_1' }, { id: 'cfm_2' }] });
    });
  });

  describe('under an audit org', () => {
    beforeEach(() => seed('audit'));

    it('serves the member and records the wildcard', async () => {
      const { access, controller } = services();

      await expect(access.can({ org_id: ORG, principal_type: 'user', principal_id: member.user_id, permission: 'cloud_fs:read', resource: mountRead('cfm_2') }))
        .resolves.toMatchObject({ allowed: true });
      await expect(controller.browse(ORG, member, {})).resolves.toMatchObject({ mount_id: 'cfm_1' });
      await expect(controller.listMounts(ORG, reader)).resolves.toMatchObject({ mounts: [{ id: 'cfm_1' }, { id: 'cfm_2' }] });
      expect(store.findings('access.org_data_role_wildcard')[0]).toMatchObject({ profile: 'audit', actor_id: member.user_id });
    });
  });

  describe('under a legacy org', () => {
    beforeEach(() => seed('legacy'));

    it('changes nothing and records nothing', async () => {
      const { access, controller } = services();

      await expect(access.can({ org_id: ORG, principal_type: 'user', principal_id: member.user_id, permission: 'cloud_fs:read', resource: mountRead('cfm_2') }))
        .resolves.toMatchObject({ allowed: true });
      await expect(controller.browse(ORG, reader, {})).resolves.toMatchObject({ mount_id: 'cfm_1' });
      await expect(controller.listMounts(ORG, reader)).resolves.toMatchObject({ mounts: [{ id: 'cfm_1' }, { id: 'cfm_2' }] });
      expect(store.findings()).toEqual([]);
    });
  });
});
