import type { Db } from '../client.js';
import type { Org } from './orgs.js';
import type { Project } from './projects.js';

export type MembershipRole = 'owner' | 'admin' | 'member';

export interface OrgMembership {
  id: string;
  org_id: string;
  user_id: string;
  role: MembershipRole;
  created_at: Date;
  updated_at: Date;
}

export interface OrgMembershipWithUser extends OrgMembership {
  email: string;
  display_name: string | null;
}

export interface ProjectMembership {
  id: string;
  project_id: string;
  user_id: string;
  role: MembershipRole;
  created_at: Date;
  updated_at: Date;
}

export interface ProjectMembershipWithUser extends ProjectMembership {
  email: string;
  display_name: string | null;
}

/**
 * SQL condition: the user holds a binding that grants `permission` on project
 * `p`, as permission checks apply bindings: the role belongs to the project's
 * org, the binding is on the project or org-wide, and it is held directly or
 * through an access group of that org.
 */
export function projectBindingExists(db: Db, userId: string, permission: string) {
  return db`
    EXISTS (
      SELECT 1 FROM access_bindings b
      JOIN access_roles ar ON ar.id = b.role_id
      WHERE ar.org_id = p.org_id
        AND (b.project_id IS NULL OR b.project_id = p.id)
        AND ${permission}::text = ANY(ar.permissions)
        AND (
          (b.principal_type = 'user' AND b.principal_id = ${userId})
          OR (b.principal_type = 'group' AND b.principal_id IN (
            SELECT gm.group_id FROM access_group_members gm
            JOIN access_groups g ON g.id = gm.group_id
            WHERE g.org_id = p.org_id
              AND gm.principal_type = 'user' AND gm.principal_id = ${userId}
          ))
        )
    )
  `;
}

export function membershipQueries(db: Db) {
  return {
    async findOrgMembership(userId: string, orgId: string): Promise<OrgMembership | null> {
      const [row] = await db<OrgMembership[]>`
        SELECT * FROM org_memberships WHERE user_id = ${userId} AND org_id = ${orgId}
      `;
      return row ?? null;
    },

    async findProjectMembership(userId: string, projectId: string): Promise<ProjectMembership | null> {
      const [row] = await db<ProjectMembership[]>`
        SELECT * FROM project_memberships
        WHERE user_id = ${userId} AND project_id = ${projectId}
      `;
      return row ?? null;
    },

    async upsertOrgMembership(
      orgId: string,
      userId: string,
      role: MembershipRole,
    ): Promise<OrgMembership> {
      const [row] = await db<OrgMembership[]>`
        INSERT INTO org_memberships (org_id, user_id, role)
        VALUES (${orgId}, ${userId}, ${role})
        ON CONFLICT (org_id, user_id) DO UPDATE
        SET role = EXCLUDED.role, updated_at = NOW()
        RETURNING *
      `;
      return row;
    },

    async upsertProjectMembership(
      projectId: string,
      userId: string,
      role: MembershipRole,
    ): Promise<ProjectMembership> {
      const [row] = await db<ProjectMembership[]>`
        INSERT INTO project_memberships (project_id, user_id, role)
        VALUES (${projectId}, ${userId}, ${role})
        ON CONFLICT (project_id, user_id) DO UPDATE
        SET role = EXCLUDED.role, updated_at = NOW()
        RETURNING *
      `;
      return row;
    },

    async listOrgsForUser(userId: string, options: { include_deleted?: boolean; limit?: number; offset?: number }): Promise<Org[]> {
      const limit = options.limit ?? 10;
      const offset = options.offset ?? 0;
      const includeDeleted = options.include_deleted ?? false;

      if (includeDeleted) {
        return db<Org[]>`
          SELECT o.*
          FROM orgs o
          JOIN org_memberships m ON m.org_id = o.id
          WHERE m.user_id = ${userId}
          ORDER BY o.created_at DESC
          LIMIT ${limit} OFFSET ${offset}
        `;
      }

      return db<Org[]>`
        SELECT o.*
        FROM orgs o
        JOIN org_memberships m ON m.org_id = o.id
        WHERE m.user_id = ${userId} AND o.deleted_at IS NULL
        ORDER BY o.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    },

    async listOrgMembershipsForUser(userId: string): Promise<OrgMembership[]> {
      const rows = await db<OrgMembership[]>`
        SELECT id, org_id, user_id, role, created_at, updated_at
        FROM org_memberships
        WHERE user_id = ${userId}
      `;
      return rows;
    },

    async listProjectMembershipsForUser(
      userId: string,
      options: { org_id?: string } = {},
    ): Promise<ProjectMembership[]> {
      const orgId = options.org_id ?? null;
      return db<ProjectMembership[]>`
        SELECT
          pm.id,
          pm.project_id,
          pm.user_id,
          pm.role,
          pm.created_at,
          pm.updated_at
        FROM project_memberships pm
        JOIN projects p ON p.id = pm.project_id
        WHERE pm.user_id = ${userId}
          AND (${orgId}::text IS NULL OR p.org_id = ${orgId})
      `;
    },

    /**
     * Projects a user reaches by project membership or org membership, each
     * marked `implicit_access` when only the org member role reaches it (no
     * project membership, no binding granting `projects:read` there; see
     * projectBindingExists). Under a strict profile
     * (the project's, else its org's, else `instance_profile`) the org member
     * role reaches nothing, so those projects are left out.
     */
    async listProjectsForUser(
      userId: string,
      options: {
        include_deleted?: boolean;
        limit?: number;
        offset?: number;
        org_id?: string;
        instance_profile?: string | null;
      },
    ): Promise<Array<Project & { implicit_access: boolean }>> {
      const limit = options.limit ?? 10;
      const offset = options.offset ?? 0;
      const includeDeleted = options.include_deleted ?? false;
      const orgIdParam = options.org_id ?? null;
      const instanceProfile = options.instance_profile ?? null;

      return db<Array<Project & { implicit_access: boolean }>>`
        SELECT p.*, a.implicit_access
        FROM projects p
        JOIN orgs o ON o.id = p.org_id
        CROSS JOIN LATERAL (
          SELECT
            EXISTS (SELECT 1 FROM project_memberships pm WHERE pm.project_id = p.id AND pm.user_id = ${userId}) AS via_project,
            (SELECT om.role FROM org_memberships om WHERE om.org_id = p.org_id AND om.user_id = ${userId}) AS org_role,
            ${projectBindingExists(db, userId, 'projects:read')} AS via_binding
        ) r
        CROSS JOIN LATERAL (
          SELECT (NOT r.via_project AND r.org_role = 'member' AND NOT r.via_binding) AS implicit_access
        ) a
        WHERE (r.via_project OR r.org_role IS NOT NULL)
          AND NOT (a.implicit_access AND COALESCE(p.security_profile, o.security_profile, ${instanceProfile}::text, 'legacy') = 'strict')
          AND (${includeDeleted}::boolean OR p.deleted_at IS NULL)
          AND (${orgIdParam}::text IS NULL OR p.org_id = ${orgIdParam})
        ORDER BY p.created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    },

    async listOrgMembers(orgId: string): Promise<OrgMembershipWithUser[]> {
      return db<OrgMembershipWithUser[]>`
        SELECT om.*, u.email, u.display_name
        FROM org_memberships om
        JOIN users u ON u.id = om.user_id
        WHERE om.org_id = ${orgId}
        ORDER BY om.created_at ASC
      `;
    },

    async removeOrgMembership(orgId: string, userId: string): Promise<boolean> {
      const rows = await db`
        DELETE FROM org_memberships
        WHERE org_id = ${orgId} AND user_id = ${userId}
        RETURNING id
      `;
      return rows.length > 0;
    },

    async listProjectMembers(projectId: string): Promise<ProjectMembershipWithUser[]> {
      return db<ProjectMembershipWithUser[]>`
        SELECT pm.*, u.email, u.display_name
        FROM project_memberships pm
        JOIN users u ON u.id = pm.user_id
        WHERE pm.project_id = ${projectId}
        ORDER BY pm.created_at ASC
      `;
    },

    async searchOrgMembers(orgId: string, query: string): Promise<OrgMembershipWithUser[]> {
      // Escape SQL LIKE wildcard characters in user input
      const escaped = query.replace(/[%_\\]/g, (ch) => `\\${ch}`);
      const pattern = `${escaped}%`;
      return db<OrgMembershipWithUser[]>`
        SELECT om.*, u.email, u.display_name
        FROM org_memberships om
        JOIN users u ON u.id = om.user_id
        WHERE om.org_id = ${orgId}
          AND (u.email ILIKE ${pattern} OR u.display_name ILIKE ${pattern})
        ORDER BY u.email
        LIMIT 20
      `;
    },

    /** Remove a user's memberships on every project of an org; returns how many. */
    async removeProjectMembershipsInOrg(orgId: string, userId: string): Promise<number> {
      const rows = await db<{ id: string }[]>`
        DELETE FROM project_memberships pm
        USING projects p
        WHERE pm.project_id = p.id
          AND p.org_id = ${orgId}
          AND pm.user_id = ${userId}
        RETURNING pm.id
      `;
      return rows.length;
    },

    async removeProjectMembership(projectId: string, userId: string): Promise<boolean> {
      const rows = await db`
        DELETE FROM project_memberships
        WHERE project_id = ${projectId} AND user_id = ${userId}
        RETURNING id
      `;
      return rows.length > 0;
    },
  };
}
