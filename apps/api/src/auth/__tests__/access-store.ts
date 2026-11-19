/**
 * In-memory stand-ins for the tables that decide who may do what: orgs,
 * projects (with their security profiles), memberships, custom role bindings,
 * access groups, system settings and security findings.
 *
 * Specs install `accessStore.queries` over `@eve/db` with `vi.mock` and seed
 * the store per test. It imports nothing at runtime, so a mock factory can
 * import it without a cycle.
 */

type Role = 'owner' | 'admin' | 'member';
type Profile = 'legacy' | 'audit' | 'strict' | null;
type Scope = Record<string, unknown> | null;

interface OrgRow { id: string; slug: string; security_profile: Profile }
interface ProjectRow {
  id: string; org_id: string; slug: string; name: string; security_profile: Profile;
  deleted_at: Date | null; created_at: Date; updated_at: Date; repo_url: string | null; branch: string | null;
}
interface MembershipRow { user_id: string; role: Role }
interface BindingRow {
  id: string; org_id: string; role_name: string; permissions: string[];
  principal_type: 'user' | 'service_principal' | 'group'; principal_id: string;
  project_id: string | null; scope_json: Scope;
}
interface GroupMemberRow { group_id: string; org_id: string; principal_type: string; principal_id: string }

function createAccessStore() {
  const state = {
    orgs: [] as OrgRow[],
    projects: [] as ProjectRow[],
    orgMemberships: [] as Array<MembershipRow & { org_id: string }>,
    projectMemberships: [] as Array<MembershipRow & { project_id: string }>,
    bindings: [] as BindingRow[],
    groupMembers: [] as GroupMemberRow[],
    settings: new Map<string, string>(),
    findings: [] as Array<{ rule: string; profile: string; org_id: string | null; project_id: string | null; actor_type: string; actor_id: string; detail: Record<string, unknown> }>,
  };

  const projectById = (id: string) => state.projects.find((p) => p.id === id && !p.deleted_at) ?? null;
  const projectOrg = (projectId: string) => state.projects.find((p) => p.id === projectId)?.org_id;
  const now = new Date('2026-11-18T00:00:00Z');

  /** Bindings that apply to a principal in an org, for a project if given (org-wide ones always). */
  function applicableBindings(orgId: string, principalType: string, principalId: string, projectId?: string) {
    const groupIds = state.groupMembers
      .filter((m) => m.org_id === orgId && m.principal_type === principalType && m.principal_id === principalId)
      .map((m) => m.group_id);
    return state.bindings
      .filter((b) => b.org_id === orgId)
      .filter((b) => (b.principal_type === principalType && b.principal_id === principalId)
        || (b.principal_type === 'group' && groupIds.includes(b.principal_id)))
      .filter((b) => b.project_id === null || (projectId !== undefined && b.project_id === projectId))
      .map((b) => ({
        ...b,
        role_id: `role_${b.role_name}`,
        role_permissions: b.permissions,
        created_by: null,
        created_at: now,
        matched_via: b.principal_type === 'group' ? 'group' : 'direct',
        matched_group_id: b.principal_type === 'group' ? b.principal_id : null,
        matched_group_slug: null,
      }));
  }

  /** A binding on this very project, held directly or through a group. */
  function hasProjectBinding(userId: string, projectId: string): boolean {
    const orgId = projectOrg(projectId);
    return applicableBindings(orgId ?? '', 'user', userId, projectId).some((b) => b.project_id === projectId);
  }

  function effectiveProfile(project: ProjectRow, instance: string | null | undefined): string {
    const org = state.orgs.find((o) => o.id === project.org_id);
    return project.security_profile ?? org?.security_profile ?? instance ?? 'legacy';
  }

  const memberships = {
    findOrgMembership: async (userId: string, orgId: string) =>
      state.orgMemberships.find((m) => m.user_id === userId && m.org_id === orgId) ?? null,
    findProjectMembership: async (userId: string, projectId: string) =>
      state.projectMemberships.find((m) => m.user_id === userId && m.project_id === projectId) ?? null,
    listOrgMembers: async (orgId: string) =>
      state.orgMemberships.filter((m) => m.org_id === orgId).map((m) => ({ ...m, email: `${m.user_id}@example.com`, display_name: null })),
    listProjectMembershipsForUser: async (userId: string, options: { org_id?: string } = {}) =>
      state.projectMemberships.filter((m) => m.user_id === userId && (!options.org_id || projectOrg(m.project_id) === options.org_id)),
    removeOrgMembership: async (orgId: string, userId: string) => {
      const before = state.orgMemberships.length;
      state.orgMemberships = state.orgMemberships.filter((m) => !(m.org_id === orgId && m.user_id === userId));
      return state.orgMemberships.length < before;
    },
    removeProjectMembershipsInOrg: async (orgId: string, userId: string) => {
      const before = state.projectMemberships.length;
      state.projectMemberships = state.projectMemberships.filter((m) => !(m.user_id === userId && projectOrg(m.project_id) === orgId));
      return before - state.projectMemberships.length;
    },
    /** The query's contract: implicit-only projects whose effective profile is strict are left out. */
    listProjectsForUser: async (userId: string, options: { org_id?: string; instance_profile?: string | null } = {}) =>
      state.projects
        .filter((p) => !p.deleted_at && (!options.org_id || p.org_id === options.org_id))
        .map((p) => {
          const viaProject = state.projectMemberships.some((m) => m.user_id === userId && m.project_id === p.id);
          const orgRole = state.orgMemberships.find((m) => m.user_id === userId && m.org_id === p.org_id)?.role;
          if (!viaProject && !orgRole) return null;
          const implicit = !viaProject && orgRole === 'member' && !hasProjectBinding(userId, p.id);
          if (implicit && effectiveProfile(p, options.instance_profile) === 'strict') return null;
          return { ...p, implicit_access: implicit };
        })
        .filter(<T>(row: T | null): row is T => row !== null),
  };

  const projects = {
    findById: async (id: string) => projectById(id),
    list: async () => state.projects.filter((p) => !p.deleted_at),
  };

  const orgs = {
    findById: async (id: string) => state.orgs.find((o) => o.id === id) ?? null,
    findBySlug: async (slug: string) => state.orgs.find((o) => o.slug === slug) ?? null,
  };

  const accessRoles = {
    getEffectiveCustomPermissions: async (principalType: string, principalId: string, orgId: string, projectId?: string) =>
      [...new Set(applicableBindings(orgId, principalType, principalId, projectId).flatMap((b) => b.permissions))],
    listApplicableBindings: async (params: { orgId: string; principalType: string; principalId: string; projectId?: string }) =>
      applicableBindings(params.orgId, params.principalType, params.principalId, params.projectId),
    listBindings: async (params: { orgId?: string; principalType?: string; principalId?: string }) =>
      state.bindings.filter((b) => (!params.orgId || b.org_id === params.orgId)
        && (!params.principalType || b.principal_type === params.principalType)
        && (!params.principalId || b.principal_id === params.principalId)),
    deleteBindingsForPrincipal: async (orgId: string, principalType: string, principalId: string) => {
      const before = state.bindings.length;
      state.bindings = state.bindings.filter((b) => !(b.org_id === orgId && b.principal_type === principalType && b.principal_id === principalId));
      return before - state.bindings.length;
    },
  };

  const accessGroups = {
    listGroupIdsForPrincipal: async (orgId: string, principalType: string, principalId: string) =>
      state.groupMembers.filter((m) => m.org_id === orgId && m.principal_type === principalType && m.principal_id === principalId).map((m) => m.group_id),
    listGroupsForPrincipal: async () => [],
    removeMember: async (groupId: string, principalType: string, principalId: string) => {
      const before = state.groupMembers.length;
      state.groupMembers = state.groupMembers.filter((m) => !(m.group_id === groupId && m.principal_type === principalType && m.principal_id === principalId));
      return state.groupMembers.length < before;
    },
    findGroupById: async (orgId: string, groupId: string) =>
      state.groupMembers.some((m) => m.org_id === orgId && m.group_id === groupId)
        ? { id: groupId, slug: groupId, name: groupId }
        : null,
    findGroupBySlug: async () => null,
  };

  const servicePrincipals = {
    getServicePrincipal: async () => null,
    listTokens: async () => [],
  };

  const settings = {
    get: async (key: string) => (state.settings.has(key) ? { key, value: state.settings.get(key) } : null),
  };

  const security = {
    getProfiles: async (scope: { orgId?: string | null; projectId?: string | null }) => {
      const project = scope.projectId ? state.projects.find((p) => p.id === scope.projectId) : undefined;
      const orgId = project?.org_id ?? scope.orgId ?? null;
      return {
        org_id: orgId,
        org_profile: state.orgs.find((o) => o.id === orgId)?.security_profile ?? null,
        project_profile: project?.security_profile ?? null,
      };
    },
    recordFinding: async (finding: Record<string, unknown>) => {
      state.findings.push(finding as (typeof state.findings)[number]);
    },
  };

  const orgQueryRows = {
    /** Today's query: every project the user reaches, by project membership or by any org role. */
    getAccessibleProjectIds: async (orgId: string, userId: string) =>
      state.projects
        .filter((p) => p.org_id === orgId && !p.deleted_at)
        .filter((p) => state.projectMemberships.some((m) => m.user_id === userId && m.project_id === p.id)
          || state.orgMemberships.some((m) => m.user_id === userId && m.org_id === orgId))
        .map((p) => p.id),
    /** The same projects, each marked when the org member role alone reaches it. */
    listAccessibleProjects: async (orgId: string, userId: string) =>
      state.projects
        .filter((p) => p.org_id === orgId && !p.deleted_at)
        .map((p) => {
          const viaProject = state.projectMemberships.some((m) => m.user_id === userId && m.project_id === p.id);
          const orgRole = state.orgMemberships.find((m) => m.user_id === userId && m.org_id === orgId)?.role;
          if (!viaProject && !orgRole) return null;
          return { id: p.id, implicit_access: !viaProject && orgRole === 'member' && !hasProjectBinding(userId, p.id) };
        })
        .filter(<T>(row: T | null): row is T => row !== null),
  };

  /** Raw SQL the services run directly: project and org lookups by id or slug. */
  const db = Object.assign(
    async (strings: TemplateStringsArray, ...values: unknown[]) => {
      const sql = strings.join('?');
      const [value] = values;
      if (/FROM orgs/.test(sql)) {
        return state.orgs.filter((o) => o.id === value || o.slug === value).map((o) => ({ id: o.id }));
      }
      if (/FROM projects/.test(sql)) {
        let rows = state.projects.filter((p) => (/WHERE id =/.test(sql) ? p.id === value : p.slug === value));
        if (/deleted_at IS NULL/.test(sql)) rows = rows.filter((p) => !p.deleted_at);
        return rows.map((p) => ({ id: p.id, org_id: p.org_id, deleted_at: p.deleted_at }));
      }
      return [];
    },
    { begin: async <T>(fn: (tx: unknown) => Promise<T>) => fn(db), json: (value: unknown) => value },
  );

  return {
    state,
    db,
    queries: {
      membershipQueries: () => memberships,
      projectQueries: () => projects,
      orgQueries: () => orgs,
      accessRoleQueries: () => accessRoles,
      accessGroupQueries: () => accessGroups,
      servicePrincipalQueries: () => servicePrincipals,
      systemSettingsQueries: () => settings,
      securityQueries: () => security,
      orgQueryQueries: () => orgQueryRows,
    },
    reset() {
      state.orgs = [];
      state.projects = [];
      state.orgMemberships = [];
      state.projectMemberships = [];
      state.bindings = [];
      state.groupMembers = [];
      state.settings.clear();
      state.findings = [];
    },
    addOrg(id: string, slug: string, profile: Profile = null) {
      state.orgs.push({ id, slug, security_profile: profile });
    },
    addProject(id: string, orgId: string, slug: string, profile: Profile = null) {
      state.projects.push({
        id, org_id: orgId, slug, name: slug, security_profile: profile,
        deleted_at: null, created_at: now, updated_at: now, repo_url: null, branch: null,
      });
    },
    setInstanceProfile(profile: 'legacy' | 'audit' | 'strict') {
      state.settings.set('security.profile', profile);
    },
    joinOrg(userId: string, orgId: string, role: Role) {
      state.orgMemberships.push({ user_id: userId, org_id: orgId, role });
    },
    joinProject(userId: string, projectId: string, role: Role) {
      state.projectMemberships.push({ user_id: userId, project_id: projectId, role });
    },
    bind(binding: { org_id: string; principal_id: string; permissions: string[]; project_id?: string | null; scope_json?: Scope; principal_type?: BindingRow['principal_type']; role_name?: string }) {
      state.bindings.push({
        id: `bind_${state.bindings.length + 1}`,
        role_name: binding.role_name ?? 'custom',
        principal_type: binding.principal_type ?? 'user',
        project_id: binding.project_id ?? null,
        scope_json: binding.scope_json ?? null,
        org_id: binding.org_id,
        principal_id: binding.principal_id,
        permissions: binding.permissions,
      });
    },
    addToGroup(groupId: string, orgId: string, userId: string) {
      state.groupMembers.push({ group_id: groupId, org_id: orgId, principal_type: 'user', principal_id: userId });
    },
    findings(rule?: string) {
      return state.findings.filter((f) => !rule || f.rule === rule);
    },
  };
}

export const accessStore = createAccessStore();
