import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { RbacService } from './rbac.service.js';
import { AccessService } from './access.service.js';
import { PermissionGuard } from './permission.guard.js';
import { PERMISSION_KEY } from './permission.decorator.js';
import { SecurityService } from '../security/security.service.js';
import { AccessController } from './auth.access.controller.js';
import type { AuthUser } from './auth.types.js';
import { accessStore as store } from './__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('./__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

const ORG = 'org_a';
const PROJECT = 'proj_a';
const member: AuthUser = { user_id: 'user_member' };
const orgAdmin: AuthUser = { user_id: 'user_admin' };
const projectMember: AuthUser = { user_id: 'user_pm' };

function services() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  return { security, rbac, access };
}

function guardFor(rbac: RbacService, required: string[]) {
  const reflector = { getAllAndOverride: (key: string) => (key === PERMISSION_KEY ? required : undefined) };
  return new PermissionGuard({ isEnabled: () => true } as never, rbac, reflector as never);
}

function projectRequest(user: AuthUser, project: string, path: string) {
  const request = { user, params: { project_id: project }, url: `/projects/${project}/${path}` };
  return {
    switchToHttp: () => ({ getRequest: () => request }),
    getHandler: () => function handler() {},
    getClass: () => class Controller {},
  } as never;
}

function seed(profile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme');
  store.addProject(PROJECT, ORG, 'alpha', profile);
  store.joinOrg(member.user_id, ORG, 'member');
  store.joinOrg(orgAdmin.user_id, ORG, 'admin');
  store.joinOrg(projectMember.user_id, ORG, 'member');
  store.joinProject(projectMember.user_id, PROJECT, 'member');
}

describe('the project wall (P1-5)', () => {
  describe('under a strict project', () => {
    beforeEach(() => seed('strict'));

    it('refuses an org member with no project membership or binding the project secrets and job creation', async () => {
      const { rbac } = services();

      await expect(guardFor(rbac, ['secrets:read']).canActivate(projectRequest(member, PROJECT, 'secrets')))
        .rejects.toBeInstanceOf(ForbiddenException);
      await expect(guardFor(rbac, ['jobs:write']).canActivate(projectRequest(member, PROJECT, 'jobs')))
        .rejects.toBeInstanceOf(ForbiddenException);
      await expect(rbac.requirePermissions(member, PROJECT, ['jobs:write'])).rejects.toBeInstanceOf(ForbiddenException);
      expect(store.findings('access.implicit_project')[0]).toMatchObject({
        profile: 'strict', project_id: PROJECT, actor_type: 'user', actor_id: member.user_id,
      });
    });

    it('leaves org admins and project members as they are, and records nothing for them', async () => {
      const { rbac } = services();

      await expect(guardFor(rbac, ['secrets:read']).canActivate(projectRequest(orgAdmin, PROJECT, 'secrets'))).resolves.toBe(true);
      await expect(guardFor(rbac, ['jobs:write']).canActivate(projectRequest(projectMember, PROJECT, 'jobs'))).resolves.toBe(true);
      await expect(rbac.requirePermissions(projectMember, PROJECT, ['jobs:write', 'secrets:read'])).resolves.toBeUndefined();
      expect(store.findings()).toEqual([]);
    });

    it('gives a member holding a binding on the project that binding, and only that', async () => {
      store.bind({ org_id: ORG, principal_id: member.user_id, project_id: PROJECT, permissions: ['jobs:read'] });
      const { rbac } = services();

      await expect(guardFor(rbac, ['jobs:read']).canActivate(projectRequest(member, PROJECT, 'jobs'))).resolves.toBe(true);
      await expect(guardFor(rbac, ['jobs:write']).canActivate(projectRequest(member, PROJECT, 'jobs')))
        .rejects.toBeInstanceOf(ForbiddenException);
    });

    it('refuses the member role on the project to an org member', async () => {
      const { rbac } = services();

      await expect(rbac.requireProjectRole(member.user_id, PROJECT, 'member')).rejects.toBeInstanceOf(ForbiddenException);
      await expect(rbac.requireProjectRole(orgAdmin.user_id, PROJECT, 'member')).resolves.toBeUndefined();
    });

    it('withholds the org member role in AccessService checks on the project', async () => {
      const { access } = services();
      const can = (principal_id: string, permission: string) =>
        access.can({ org_id: ORG, principal_type: 'user', principal_id, project_id: PROJECT, permission });

      await expect(can(member.user_id, 'jobs:write')).resolves.toMatchObject({ allowed: false });
      await expect(can(member.user_id, 'envdb:read')).resolves.toMatchObject({ allowed: false });
      await expect(can(orgAdmin.user_id, 'jobs:write')).resolves.toMatchObject({ allowed: true });
      await expect(can(projectMember.user_id, 'jobs:write')).resolves.toMatchObject({ allowed: true });
      // Without a project the org role is the org role.
      await expect(access.can({ org_id: ORG, principal_type: 'user', principal_id: member.user_id, permission: 'orgs:read' }))
        .resolves.toMatchObject({ allowed: true });
    });
  });

  describe('under an audit project', () => {
    beforeEach(() => seed('audit'));

    it('lets the org member in and records each grant that came only from the org member role', async () => {
      const { rbac, access } = services();

      await expect(guardFor(rbac, ['secrets:read']).canActivate(projectRequest(member, PROJECT, 'secrets'))).resolves.toBe(true);
      await expect(rbac.requirePermissions(member, PROJECT, ['jobs:write'])).resolves.toBeUndefined();
      await expect(access.can({ org_id: ORG, principal_type: 'user', principal_id: member.user_id, project_id: PROJECT, permission: 'jobs:write' }))
        .resolves.toMatchObject({ allowed: true });

      const findings = store.findings('access.implicit_project');
      expect(findings.length).toBeGreaterThan(0);
      expect(findings[0]).toMatchObject({ profile: 'audit', org_id: ORG, project_id: PROJECT, actor_id: member.user_id });
    });

    it('answers `eve access can` without recording a finding', async () => {
      const { rbac, access } = services();
      const controller = new AccessController(access, rbac);

      await expect(controller.can(ORG, 'user', member.user_id, PROJECT, 'jobs:write', undefined, undefined, undefined, orgAdmin))
        .resolves.toMatchObject({ allowed: true });
      expect(store.findings()).toEqual([]);
    });

    it('records nothing when the request does not depend on the org member role', async () => {
      store.bind({ org_id: ORG, principal_id: member.user_id, project_id: PROJECT, permissions: ['jobs:read'] });
      const { rbac } = services();

      await expect(guardFor(rbac, ['jobs:read']).canActivate(projectRequest(member, PROJECT, 'jobs'))).resolves.toBe(true);
      await expect(guardFor(rbac, ['secrets:read']).canActivate(projectRequest(orgAdmin, PROJECT, 'secrets'))).resolves.toBe(true);
      expect(store.findings()).toEqual([]);
    });
  });

  describe('under a legacy project', () => {
    beforeEach(() => seed('legacy'));

    it('changes nothing and records nothing', async () => {
      const { rbac, access } = services();

      await expect(guardFor(rbac, ['secrets:read']).canActivate(projectRequest(member, PROJECT, 'secrets'))).resolves.toBe(true);
      await expect(rbac.requireProjectRole(member.user_id, PROJECT, 'member')).resolves.toBeUndefined();
      await expect(access.can({ org_id: ORG, principal_type: 'user', principal_id: member.user_id, project_id: PROJECT, permission: 'jobs:write' }))
        .resolves.toMatchObject({ allowed: true });
      expect(store.findings()).toEqual([]);
    });
  });

  describe('a failed project lookup', () => {
    beforeEach(() => seed('legacy'));

    it('refuses under a strict instance instead of granting the member set', async () => {
      store.setInstanceProfile('strict');
      const { rbac } = services();

      await expect(rbac.resolveEffectivePermissions(member, 'proj_missing')).resolves.toEqual(new Set());
      await expect(rbac.requirePermissions(member, 'proj_missing', ['jobs:read'])).rejects.toBeInstanceOf(ForbiddenException);
      expect(store.findings('access.unresolved_project')[0]).toMatchObject({ profile: 'strict', actor_id: member.user_id });
    });

    it('still grants the member set under legacy', async () => {
      const { rbac } = services();

      await expect(rbac.requirePermissions(member, 'proj_missing', ['jobs:read'])).resolves.toBeUndefined();
      expect(store.findings()).toEqual([]);
    });

    it('is an error, not the member set, when the profile lookup fails', async () => {
      seed('strict');
      store.setInstanceProfile('audit');
      const { rbac, security } = services();
      const queries = (security as unknown as { security: { getProfiles: (...args: unknown[]) => Promise<unknown> } }).security;
      const getProfiles = queries.getProfiles;
      queries.getProfiles = async () => {
        throw new Error('connection reset');
      };
      try {
        await expect(rbac.requirePermissions(member, PROJECT, ['secrets:read'])).rejects.toThrow('connection reset');
        await expect(rbac.resolveEffectivePermissions(member, PROJECT)).rejects.toThrow('connection reset');
      } finally {
        queries.getProfiles = getProfiles;
      }
    });

    it('judges a deleted project named by id under that project\'s own profile', async () => {
      seed('strict');
      store.setInstanceProfile('audit');
      store.state.projects[0].deleted_at = new Date('2026-11-18T00:00:00Z');
      const { rbac } = services();

      await expect(rbac.requirePermissions(member, PROJECT, ['jobs:read'])).rejects.toBeInstanceOf(ForbiddenException);
      expect(store.findings('access.unresolved_project')[0]).toMatchObject({ profile: 'strict', project_id: PROJECT });
    });

    it('grants the member set for a project that cannot be found, under an audit instance', async () => {
      seed('strict');
      store.setInstanceProfile('audit');
      const { rbac } = services();

      await expect(rbac.requirePermissions(member, 'proj_missing', ['jobs:read'])).resolves.toBeUndefined();
      expect(store.findings('access.unresolved_project')[0]).toMatchObject({ profile: 'audit' });
    });
  });

  describe('project-scoped bindings (always on)', () => {
    beforeEach(() => {
      seed('legacy');
      // A user outside the org holding only a binding on the project.
      store.bind({ org_id: ORG, principal_id: 'user_outside', project_id: PROJECT, permissions: ['jobs:read', 'threads:read'] });
      store.bind({ org_id: ORG, principal_id: 'grp_ops', principal_type: 'group', project_id: PROJECT, permissions: ['builds:read'] });
      store.addToGroup('grp_ops', ORG, 'user_outside');
    });

    it('apply when the route addresses the project by slug', async () => {
      const { rbac } = services();
      const outsider: AuthUser = { user_id: 'user_outside' };

      await expect(guardFor(rbac, ['jobs:read']).canActivate(projectRequest(outsider, 'alpha', 'jobs'))).resolves.toBe(true);
      await expect(rbac.requirePermissions(outsider, 'alpha', ['threads:read', 'builds:read'])).resolves.toBeUndefined();
    });

    it('apply in AccessService checks that name the project by slug', async () => {
      const { access } = services();

      await expect(access.can({ org_id: ORG, principal_type: 'user', principal_id: 'user_outside', project_id: 'alpha', permission: 'jobs:read' }))
        .resolves.toMatchObject({ allowed: true });
      await expect(access.can({ org_id: ORG, principal_type: 'group', principal_id: 'grp_ops', project_id: 'alpha', permission: 'builds:read' }))
        .resolves.toMatchObject({ allowed: true });
    });
  });
});
