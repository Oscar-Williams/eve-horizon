import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException } from '@nestjs/common';
import { AccessRolesController } from './auth.access-roles.controller.js';
import type { AuthUser } from './auth.types.js';

const store = vi.hoisted(() => ({
  projects: new Map<string, { id: string; org_id: string; slug: string; deleted_at: Date | null }>(),
  createBinding: vi.fn(async (id: string, roleId: string, principalType: string, principalId: string, projectId: string | null) => ({
    id, role_id: roleId, principal_type: principalType, principal_id: principalId, project_id: projectId,
    scope_json: null, created_by: 'user_admin', created_at: new Date('2026-11-19T00:00:00Z'),
  })),
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    accessRoleQueries: () => ({
      getRoleByName: async (orgId: string, name: string) => ({
        id: 'role_viewer', org_id: orgId, name, scope: 'project', permissions: ['jobs:read'],
      }),
      createBinding: store.createBinding,
    }),
    accessGroupQueries: () => ({ findGroupById: async () => null }),
    projectQueries: () => ({
      findById: async (id: string) => store.projects.get(id) ?? null,
      findBySlug: async (orgId: string, slug: string) =>
        [...store.projects.values()].find((p) => p.org_id === orgId && p.slug === slug) ?? null,
    }),
  };
});

const admin: AuthUser = { user_id: 'user_admin' };
const rbac = {
  requireOrgRole: vi.fn(async () => undefined),
  getEffectivePermissions: vi.fn(async () => new Set(['jobs:read'])),
};

function controller() {
  const db = Object.assign(async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?');
    if (/FROM projects/.test(sql)) {
      const [first, second] = values as string[];
      return [...store.projects.values()].filter((p) => !p.deleted_at && (p.id === first || (p.slug === first && p.org_id === second)));
    }
    return [];
  }, { json: (value: unknown) => value });
  return new AccessRolesController(db as never, rbac as never);
}

describe('creating an access binding on a project', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    store.projects.clear();
    store.projects.set('proj_here', { id: 'proj_here', org_id: 'org_a', slug: 'here', deleted_at: null });
    store.projects.set('proj_there', { id: 'proj_there', org_id: 'org_b', slug: 'there', deleted_at: null });
  });

  it('refuses a project outside the role\'s org', async () => {
    await expect(controller().createBinding('org_a', {
      role_name: 'viewer', principal_type: 'user', principal_id: 'user_x', project_id: 'proj_there',
    } as never, admin)).rejects.toBeInstanceOf(BadRequestException);
    expect(store.createBinding).not.toHaveBeenCalled();
  });

  it('refuses a project that does not exist', async () => {
    await expect(controller().createBinding('org_a', {
      role_name: 'viewer', principal_type: 'user', principal_id: 'user_x', project_id: 'proj_missing',
    } as never, admin)).rejects.toBeInstanceOf(BadRequestException);
    expect(store.createBinding).not.toHaveBeenCalled();
  });

  it('binds a project of the role\'s org, named by id or by slug', async () => {
    await controller().createBinding('org_a', {
      role_name: 'viewer', principal_type: 'user', principal_id: 'user_x', project_id: 'proj_here',
    } as never, admin);
    await controller().createBinding('org_a', {
      role_name: 'viewer', principal_type: 'user', principal_id: 'user_x', project_id: 'here',
    } as never, admin);
    expect(store.createBinding.mock.calls.map((call) => call[4])).toEqual(['proj_here', 'proj_here']);
  });
});
