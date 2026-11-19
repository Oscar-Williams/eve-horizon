/**
 * The project wall's SQL against a migrated database: which bindings make a
 * project reachable for an org member (project listing and org queries).
 * A binding counts only when its role belongs to the project's org (and a
 * group's binding only when the group does too), and only when the role
 * grants the permission asked for: `projects:read` for the project list, the
 * listing's own permission for org queries. An org-wide binding counts.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import postgres from 'postgres';
import { membershipQueries } from './memberships.js';
import { orgQueryQueries } from './org-queries.js';
import type { Db } from '../client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 8);
const orgB = `org_pwb${suffix}`;
const orgA = `org_pwa${suffix}`;
const project = `proj_pw${suffix}`;
const user = `user_pw${suffix}`;
const roleIds: string[] = [];

describe('project wall SQL', () => {
  let db: Db;

  async function role(orgId: string, permissions: string[]): Promise<string> {
    const id = `role_pw${suffix}${roleIds.length}`;
    roleIds.push(id);
    await db`
      INSERT INTO access_roles (id, org_id, name, scope, permissions)
      VALUES (${id}, ${orgId}, ${id}, 'project', ${permissions})
    `;
    return id;
  }

  async function bind(roleId: string, principal: { type: 'user' | 'group'; id: string }, projectId: string | null) {
    await db`
      INSERT INTO access_bindings (id, role_id, principal_type, principal_id, project_id)
      VALUES (${`bind_pw${suffix}${Math.random().toString(36).slice(2, 8)}`}, ${roleId}, ${principal.type}, ${principal.id}, ${projectId})
    `;
  }

  async function group(orgId: string): Promise<string> {
    const id = `grp_pw${suffix}${Math.random().toString(36).slice(2, 6)}`;
    await db`INSERT INTO access_groups (id, org_id, name, slug) VALUES (${id}, ${orgId}, ${id}, ${id})`;
    await db`INSERT INTO access_group_members (group_id, principal_type, principal_id) VALUES (${id}, 'user', ${user})`;
    return id;
  }

  async function listed(): Promise<boolean> {
    const rows = await membershipQueries(db).listProjectsForUser(user, { org_id: orgB, instance_profile: 'audit', limit: 50 });
    return rows.some((row) => row.id === project);
  }

  async function implicitFor(permission: string): Promise<boolean | undefined> {
    const rows = await orgQueryQueries(db).listAccessibleProjects(orgB, user, permission);
    return rows.find((row) => row.id === project)?.implicit_access;
  }

  beforeAll(async () => {
    db = postgres(testDbUrl!, { max: 2 }) as unknown as Db;
    await db`INSERT INTO users (id, email) VALUES (${user}, ${`${user}@example.com`})`;
    await db`INSERT INTO orgs (id, name, slug) VALUES (${orgB}, ${orgB}, ${`pwb${suffix}`}), (${orgA}, ${orgA}, ${`pwa${suffix}`})`;
    await db`
      INSERT INTO projects (id, org_id, name, slug, repo_url, security_profile)
      VALUES (${project}, ${orgB}, ${project}, ${`pw${suffix}`}, 'https://example.com/repo.git', 'strict')
    `;
    await db`INSERT INTO org_memberships (org_id, user_id, role) VALUES (${orgB}, ${user}, 'member'), (${orgA}, ${user}, 'owner')`;
  });

  beforeEach(async () => {
    await db`DELETE FROM access_groups WHERE org_id IN (${orgA}, ${orgB})`;
    await db`DELETE FROM access_roles WHERE org_id IN (${orgA}, ${orgB})`;
  });

  afterAll(async () => {
    await db`DELETE FROM access_groups WHERE org_id IN (${orgA}, ${orgB})`;
    await db`DELETE FROM access_roles WHERE org_id IN (${orgA}, ${orgB})`;
    await db`DELETE FROM org_memberships WHERE user_id = ${user}`;
    await db`DELETE FROM projects WHERE id = ${project}`;
    await db`DELETE FROM orgs WHERE id IN (${orgA}, ${orgB})`;
    await db`DELETE FROM users WHERE id = ${user}`;
    await (db as unknown as { end: () => Promise<void> }).end();
  });

  it('withholds a strict project from an org member with no membership or binding', async () => {
    expect(await listed()).toBe(false);
    expect(await implicitFor('jobs:read')).toBe(true);
  });

  it('ignores a binding whose role belongs to another org', async () => {
    await bind(await role(orgA, ['projects:read', 'jobs:read']), { type: 'user', id: user }, project);

    expect(await listed()).toBe(false);
    expect(await implicitFor('jobs:read')).toBe(true);
  });

  it('counts a binding only for the permissions its role grants', async () => {
    await bind(await role(orgB, ['envdb:read']), { type: 'user', id: user }, project);

    expect(await listed()).toBe(false);
    expect(await implicitFor('jobs:read')).toBe(true);

    await bind(await role(orgB, ['jobs:read']), { type: 'user', id: user }, project);
    expect(await implicitFor('jobs:read')).toBe(false);
    expect(await implicitFor('events:read')).toBe(true);
  });

  it('counts an org-wide binding that grants project read', async () => {
    await bind(await role(orgB, ['projects:read']), { type: 'user', id: user }, null);

    expect(await listed()).toBe(true);
  });

  it('counts a group binding when the group and the role belong to the project\'s org', async () => {
    await bind(await role(orgB, ['jobs:read']), { type: 'group', id: await group(orgB) }, project);
    expect(await implicitFor('jobs:read')).toBe(false);
  });

  it('ignores a group binding when the group belongs to another org', async () => {
    await bind(await role(orgB, ['jobs:read']), { type: 'group', id: await group(orgA) }, project);
    expect(await implicitFor('jobs:read')).toBe(true);
  });
});
