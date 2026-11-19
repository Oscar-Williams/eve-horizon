import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException } from '@nestjs/common';
import { RbacService } from './rbac.service.js';
import { AccessService } from './access.service.js';
import { ScopedAccessService } from './scoped-access.service.js';
import { assertCanUseJobScope, jobTokenPermissionsFor } from './token-scope.js';
import { SecurityService } from '../security/security.service.js';
import type { AuthUser } from './auth.types.js';
import { accessStore as store } from './__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('./__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

const ORG = 'org_a';
const PROJECT = 'proj_a';
/** An org member who is admin of one project: the role R3-T-04 is about. */
const PROJECT_ADMIN = 'user_pa';
const ORG_ADMIN = 'user_oa';
const DEAL = '/groups/projects/deal-1';

function services() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  const scoped = new ScopedAccessService({ isEnabled: () => true } as never, access, rbac, security);
  return { access, scoped };
}

function jobToken(overrides: Partial<AuthUser> = {}): AuthUser {
  return {
    user_id: PROJECT_ADMIN,
    is_job_token: true,
    job_id: 'lab-1234abcd',
    org_id: ORG,
    project_id: PROJECT,
    permissions: ['orgfs:read', 'cloud_fs:read'],
    ...overrides,
  };
}

const readDeal = { type: 'orgfs' as const, id: `${DEAL}/brief.md`, action: 'read' as const };
const readMount = { type: 'cloud_fs' as const, id: 'cfm_1', action: 'read' as const };

function seed(orgProfile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme', orgProfile);
  store.addProject(PROJECT, ORG, 'lab');
  store.joinOrg(PROJECT_ADMIN, ORG, 'member');
  store.joinProject(PROJECT_ADMIN, PROJECT, 'admin');
  store.joinOrg(ORG_ADMIN, ORG, 'admin');
}

describe('org files, docs and cloud-fs in jobs (P1-6)', () => {
  describe('under a strict org', () => {
    beforeEach(() => seed('strict'));

    it('gives a job token with no scope no org file or cloud-fs access', async () => {
      const { scoped } = services();

      await expect(scoped.can({ org_id: ORG, permission: 'orgfs:read', user: jobToken(), resource: readDeal })).resolves.toBe(false);
      await expect(scoped.can({ org_id: ORG, permission: 'cloud_fs:read', user: jobToken(), resource: readMount })).resolves.toBe(false);
      expect(store.findings('access.org_data_unscoped')[0]).toMatchObject({ profile: 'strict', org_id: ORG, actor_type: 'job' });
    });

    it('lets a scoped token read inside its scope', async () => {
      const { scoped } = services();
      const token = jobToken({ scope: { orgfs: { allow_prefixes: [`${DEAL}/**`] } } });

      await expect(scoped.can({ org_id: ORG, permission: 'orgfs:read', user: token, resource: readDeal })).resolves.toBe(true);
      await expect(scoped.can({ org_id: ORG, permission: 'orgfs:read', user: token, resource: { ...readDeal, id: '/groups/other/x.md' } }))
        .resolves.toBe(false);
    });

    it('gives a run no user started no org scope', async () => {
      const { scoped } = services();
      const token = jobToken({ user_id: 'system', scope: { orgfs: { allow_prefixes: [`${DEAL}/**`] } } });

      await expect(scoped.can({ org_id: ORG, permission: 'orgfs:read', user: token, resource: readDeal })).resolves.toBe(false);
      expect(store.findings('access.org_data_no_user')[0]).toMatchObject({ profile: 'strict', org_id: ORG });
    });

    it('refuses org data in a scope declared for work no user started', async () => {
      const { access } = services();
      const noUser = (userId: string | undefined, scope: Record<string, unknown>) => assertCanUseJobScope(access, {
        orgId: ORG, projectId: PROJECT, userId, scope: scope as never, context: 'Workflow step scope',
      });

      await expect(noUser(undefined, { orgfs: { read_only_prefixes: ['/**'] } })).rejects.toBeInstanceOf(BadRequestException);
      await expect(noUser('system', { cloud_fs: { allow_mount_ids: ['cfm_1'] } })).rejects.toBeInstanceOf(BadRequestException);
      // A project's env-db is not org data.
      await expect(noUser(undefined, { envdb: { schemas: ['public'] } })).resolves.toBeUndefined();
      expect(store.findings('access.org_data_no_user')[0]).toMatchObject({ profile: 'strict', org_id: ORG, actor_type: 'none' });
    });

    it('lets org owners and admins declare an org data scope outside any binding', async () => {
      const { access } = services();

      await expect(assertCanUseJobScope(access, {
        orgId: ORG, projectId: PROJECT, userId: ORG_ADMIN,
        scope: { cloud_fs: { allow_mount_ids: ['*'] } }, context: 'Workflow step scope',
      })).resolves.toBeUndefined();
      expect(store.findings('access.org_data_scope_wide')).toEqual([]);
    });

    it('refuses a declared scope of every mount from a project admin with no binding', async () => {
      const { access } = services();

      await expect(assertCanUseJobScope(access, {
        orgId: ORG, projectId: PROJECT, userId: PROJECT_ADMIN,
        scope: { cloud_fs: { allow_mount_ids: ['*'] } }, context: 'Workflow step scope',
      })).rejects.toBeInstanceOf(BadRequestException);
      expect(store.findings('access.org_data_scope_wide')[0]).toMatchObject({ profile: 'strict', org_id: ORG });
    });

    it('refuses a declared mount that only a built-in role reaches', async () => {
      const { access } = services();

      await expect(assertCanUseJobScope(access, {
        orgId: ORG, projectId: PROJECT, userId: PROJECT_ADMIN,
        scope: { cloud_fs: { allow_mount_ids: ['cfm_1'] } }, context: 'Job scope',
      })).rejects.toBeInstanceOf(BadRequestException);
    });

    it('accepts a declared scope inside the actor\'s bindings', async () => {
      store.bind({
        org_id: ORG, principal_id: PROJECT_ADMIN, project_id: PROJECT,
        permissions: ['orgfs:read', 'orgfs:write', 'cloud_fs:read'],
        scope_json: { orgfs: { allow_prefixes: ['/groups/projects/**'] }, cloud_fs: { allow_mount_ids: ['cfm_1'] } },
      });
      const { access } = services();

      await expect(assertCanUseJobScope(access, {
        orgId: ORG, projectId: PROJECT, userId: PROJECT_ADMIN,
        scope: { orgfs: { allow_prefixes: [`${DEAL}/**`] }, cloud_fs: { allow_mount_ids: ['cfm_1'] } }, context: 'Job scope',
      })).resolves.toBeUndefined();
    });

    it('stops a built-in project role implying admin over every mount', async () => {
      const { access } = services();
      const can = (principal_id: string, permission: string, resource = { ...readMount, action: 'admin' as const }) =>
        access.can({ org_id: ORG, principal_type: 'user', principal_id, project_id: PROJECT, permission, resource });

      await expect(can(PROJECT_ADMIN, 'cloud_fs:admin')).resolves.toMatchObject({ allowed: false });
      await expect(can(ORG_ADMIN, 'cloud_fs:admin')).resolves.toMatchObject({ allowed: true });
      // Project data is not org data: the project role's env-db scope stands.
      await expect(can(PROJECT_ADMIN, 'envdb:write', { type: 'envdb', id: 'public.deals', action: 'write' } as never))
        .resolves.toMatchObject({ allowed: true });
      expect(store.findings('access.org_data_role_wildcard')[0]).toMatchObject({ profile: 'strict', actor_id: PROJECT_ADMIN });
    });

    it('withholds cloud-fs admin from a project admin\'s job token', async () => {
      const { access } = services();

      await expect(jobTokenPermissionsFor(access, PROJECT_ADMIN, ORG, PROJECT, ['cloud_fs:admin', 'jobs:read']))
        .resolves.toEqual(['jobs:read']);
      await expect(jobTokenPermissionsFor(access, ORG_ADMIN, ORG, PROJECT, ['cloud_fs:admin', 'jobs:read']))
        .resolves.toEqual(['cloud_fs:admin', 'jobs:read']);
    });
  });

  describe('under an audit org', () => {
    beforeEach(() => seed('audit'));

    it('allows what strict refuses and records each case', async () => {
      const { access, scoped } = services();

      await expect(scoped.can({ org_id: ORG, permission: 'orgfs:read', user: jobToken(), resource: readDeal })).resolves.toBe(true);
      await expect(assertCanUseJobScope(access, {
        orgId: ORG, projectId: PROJECT, userId: PROJECT_ADMIN,
        scope: { cloud_fs: { allow_mount_ids: ['*'] } }, context: 'Job scope',
      })).resolves.toBeUndefined();
      await expect(jobTokenPermissionsFor(access, PROJECT_ADMIN, ORG, PROJECT, ['cloud_fs:admin']))
        .resolves.toEqual(['cloud_fs:admin']);

      await expect(assertCanUseJobScope(access, {
        orgId: ORG, projectId: PROJECT, userId: undefined,
        scope: { orgfs: { read_only_prefixes: ['/**'] } }, context: 'Workflow step scope',
      })).resolves.toBeUndefined();

      expect(store.findings('access.org_data_unscoped')[0]).toMatchObject({ profile: 'audit' });
      expect(store.findings('access.org_data_no_user')[0]).toMatchObject({ profile: 'audit', actor_type: 'none' });
      expect(store.findings('access.org_data_scope_wide')[0]).toMatchObject({ profile: 'audit' });
      expect(store.findings('access.org_data_role_wildcard')[0]).toMatchObject({ profile: 'audit' });
    });
  });

  describe('under a legacy org', () => {
    beforeEach(() => seed('legacy'));

    it('changes nothing and records nothing', async () => {
      const { access, scoped } = services();

      await expect(scoped.can({ org_id: ORG, permission: 'orgfs:read', user: jobToken(), resource: readDeal })).resolves.toBe(true);
      await expect(scoped.can({ org_id: ORG, permission: 'orgfs:read', user: jobToken({ user_id: 'system' }), resource: readDeal })).resolves.toBe(true);
      await expect(assertCanUseJobScope(access, {
        orgId: ORG, projectId: PROJECT, userId: PROJECT_ADMIN,
        scope: { cloud_fs: { allow_mount_ids: ['*'] } }, context: 'Job scope',
      })).resolves.toBeUndefined();
      await expect(jobTokenPermissionsFor(access, PROJECT_ADMIN, ORG, PROJECT, ['cloud_fs:admin']))
        .resolves.toEqual(['cloud_fs:admin']);
      expect(store.findings()).toEqual([]);
    });
  });
});
