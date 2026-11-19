import type { Db } from '../client.js';
import {
  SECURITY_PROFILE_RULESET_SETTING,
  SECURITY_PROFILE_SETTING,
  generateSecurityFindingId,
  resolveSecurityProfile,
  type SecurityGoverningScope,
  type SecurityProfile,
} from '@eve/shared';

export interface SecurityFinding {
  id: string;
  day: string;
  rule: string;
  profile: string;
  org_id: string | null;
  project_id: string | null;
  actor_type: string;
  actor_id: string;
  detail: Record<string, unknown>;
  count: number;
  first_seen: Date;
  last_seen: Date;
}

export interface NewSecurityFinding {
  id: string;
  rule: string;
  profile: string;
  org_id: string | null;
  project_id: string | null;
  actor_type: string;
  actor_id: string;
  detail: Record<string, unknown>;
}

export interface SecurityProfileRow {
  org_id: string | null;
  org_profile: string | null;
  /** The rule set the org's `strict` covers (NULL reads as 1). */
  org_ruleset?: number | null;
  project_profile: string | null;
  /** The rule set the project's `strict` covers (NULL reads as 1). */
  project_ruleset?: number | null;
}

export interface ScopeProfileRow {
  id: string;
  slug: string;
  org_id?: string;
  security_profile: string | null;
  security_profile_ruleset?: number | null;
}

export function securityQueries(db: Db) {
  return {
    /** The org and project profile columns for a scope (a project implies its org). */
    async getProfiles(scope: { orgId?: string | null; projectId?: string | null }): Promise<SecurityProfileRow> {
      if (scope.projectId) {
        const [row] = await db<SecurityProfileRow[]>`
          SELECT p.org_id,
                 o.security_profile AS org_profile, o.security_profile_ruleset AS org_ruleset,
                 p.security_profile AS project_profile, p.security_profile_ruleset AS project_ruleset
          FROM projects p JOIN orgs o ON o.id = p.org_id
          WHERE p.id = ${scope.projectId}
        `;
        if (row) return row;
      }
      if (scope.orgId) {
        // Org routes may name the org by slug; slugs are unique.
        const [row] = await db<SecurityProfileRow[]>`
          SELECT id AS org_id, security_profile AS org_profile, security_profile_ruleset AS org_ruleset,
                 NULL::text AS project_profile, NULL::integer AS project_ruleset
          FROM orgs WHERE id = ${scope.orgId} OR slug = ${scope.orgId}
          LIMIT 1
        `;
        if (row) return row;
      }
      return { org_id: scope.orgId ?? null, org_profile: null, org_ruleset: null, project_profile: null, project_ruleset: null };
    },

    /** Set an org's profile and its stamp (the rule set a `strict` covers; NULL otherwise). */
    async setOrgProfile(orgId: string, profile: string | null, ruleset: number | null = null): Promise<boolean> {
      const stamp = profile === 'strict' ? ruleset : null;
      const result = await db`
        UPDATE orgs SET security_profile = ${profile}, security_profile_ruleset = ${stamp}, updated_at = NOW()
        WHERE id = ${orgId}
      `;
      return result.count > 0;
    },

    /** Set a project's profile and its stamp (the rule set a `strict` covers; NULL otherwise). */
    async setProjectProfile(projectId: string, profile: string | null, ruleset: number | null = null): Promise<boolean> {
      const stamp = profile === 'strict' ? ruleset : null;
      const result = await db`
        UPDATE projects SET security_profile = ${profile}, security_profile_ruleset = ${stamp}, updated_at = NOW()
        WHERE id = ${projectId}
      `;
      return result.count > 0;
    },

    async listOrgProfiles(orgId?: string): Promise<ScopeProfileRow[]> {
      return orgId
        ? db<ScopeProfileRow[]>`
            SELECT id, slug, security_profile, security_profile_ruleset
            FROM orgs WHERE id = ${orgId} AND deleted_at IS NULL
          `
        : db<ScopeProfileRow[]>`
            SELECT id, slug, security_profile, security_profile_ruleset
            FROM orgs WHERE deleted_at IS NULL ORDER BY slug
          `;
    },

    async listProjectProfiles(scope: { orgId?: string; projectId?: string }): Promise<ScopeProfileRow[]> {
      if (scope.projectId) {
        return db<ScopeProfileRow[]>`
          SELECT id, slug, org_id, security_profile, security_profile_ruleset FROM projects
          WHERE id = ${scope.projectId} AND deleted_at IS NULL
        `;
      }
      if (scope.orgId) {
        return db<ScopeProfileRow[]>`
          SELECT id, slug, org_id, security_profile, security_profile_ruleset FROM projects
          WHERE org_id = ${scope.orgId} AND deleted_at IS NULL ORDER BY slug
        `;
      }
      return db<ScopeProfileRow[]>`
        SELECT id, slug, org_id, security_profile, security_profile_ruleset
        FROM projects WHERE deleted_at IS NULL ORDER BY org_id, slug
      `;
    },

    /** Add one sighting: a new row for the day, or count and last_seen on the existing one. */
    async recordFinding(finding: NewSecurityFinding): Promise<void> {
      await db`
        INSERT INTO security_findings (id, day, rule, profile, org_id, project_id, actor_type, actor_id, detail)
        VALUES (
          ${finding.id}, CURRENT_DATE, ${finding.rule}, ${finding.profile}, ${finding.org_id},
          ${finding.project_id}, ${finding.actor_type}, ${finding.actor_id}, ${db.json(finding.detail as never)}
        )
        ON CONFLICT (day, rule, COALESCE(org_id, ''), COALESCE(project_id, ''), actor_type, actor_id)
        DO UPDATE SET
          count = security_findings.count + 1,
          last_seen = NOW(),
          profile = EXCLUDED.profile,
          detail = EXCLUDED.detail
      `;
    },

    /**
     * As recordFinding, but a repeat keeps the detail the day's row was
     * first written with. For findings an unauthenticated caller can cause,
     * so a later request cannot replace what was recorded.
     */
    async recordFindingKeepingDetail(finding: NewSecurityFinding): Promise<void> {
      await db`
        INSERT INTO security_findings (id, day, rule, profile, org_id, project_id, actor_type, actor_id, detail)
        VALUES (
          ${finding.id}, CURRENT_DATE, ${finding.rule}, ${finding.profile}, ${finding.org_id},
          ${finding.project_id}, ${finding.actor_type}, ${finding.actor_id}, ${db.json(finding.detail as never)}
        )
        ON CONFLICT (day, rule, COALESCE(org_id, ''), COALESCE(project_id, ''), actor_type, actor_id)
        DO UPDATE SET
          count = security_findings.count + 1,
          last_seen = NOW(),
          profile = EXCLUDED.profile
      `;
    },

    async listFindings(options: { since: Date; orgId?: string; projectId?: string; limit?: number }): Promise<SecurityFinding[]> {
      const limit = Math.min(Math.max(options.limit ?? 500, 1), 5000);
      if (options.projectId) {
        return db<SecurityFinding[]>`
          SELECT * FROM security_findings
          WHERE last_seen >= ${options.since} AND project_id = ${options.projectId}
          ORDER BY last_seen DESC LIMIT ${limit}
        `;
      }
      if (options.orgId) {
        return db<SecurityFinding[]>`
          SELECT * FROM security_findings
          WHERE last_seen >= ${options.since} AND org_id = ${options.orgId}
          ORDER BY last_seen DESC LIMIT ${limit}
        `;
      }
      return db<SecurityFinding[]>`
        SELECT * FROM security_findings
        WHERE last_seen >= ${options.since}
        ORDER BY last_seen DESC LIMIT ${limit}
      `;
    },
  };
}

/**
 * The profile that governs a rule for a scope, outside the API, without
 * recording anything: for code that only reports what a rule means (preview
 * URLs). With a rule, a `strict` stamped before the rule's rule set gives
 * `audit`. Uncached.
 */
export async function governingSecurityProfile(
  db: Db,
  ctx: { orgId?: string | null; projectId?: string | null; governing: SecurityGoverningScope; rule?: string },
): Promise<SecurityProfile> {
  return (await resolveGoverning(db, ctx, ctx.rule)).profile;
}

async function resolveGoverning(
  db: Db,
  ctx: { orgId?: string | null; projectId?: string | null; governing: SecurityGoverningScope },
  rule: string | undefined,
): Promise<{ profile: SecurityProfile; row: SecurityProfileRow | null }> {
  const settings = await db<{ key: string; value: string }[]>`
    SELECT key, value FROM system_settings
    WHERE key IN (${SECURITY_PROFILE_SETTING}, ${SECURITY_PROFILE_RULESET_SETTING})
  `;
  const instance = settings.find((s) => s.key === SECURITY_PROFILE_SETTING)?.value ?? null;
  const instanceRuleset = settings.find((s) => s.key === SECURITY_PROFILE_RULESET_SETTING)?.value ?? null;
  const row = ctx.projectId || ctx.orgId
    ? await securityQueries(db).getProfiles({ orgId: ctx.orgId, projectId: ctx.projectId })
    : null;
  const profile = ctx.governing === 'instance'
    ? resolveSecurityProfile({ instance, instanceRuleset }, rule)
    : resolveSecurityProfile({
        project: ctx.governing === 'project' ? row?.project_profile : null,
        projectRuleset: ctx.governing === 'project' ? row?.project_ruleset : null,
        org: row?.org_profile,
        orgRuleset: row?.org_ruleset,
        instance,
        instanceRuleset,
      }, rule);
  return { profile, row };
}

/**
 * Decide a security rule outside the API (orchestrator, worker): resolve the
 * governing profile, honouring the stamps as the API does, and record a
 * finding under `audit` and `strict`. Returns the profile; the caller
 * enforces when it is `strict`. Uncached: for code that runs once per job or
 * deploy, not per request.
 */
export async function decideSecurityRule(
  db: Db,
  rule: string,
  ctx: {
    orgId?: string | null;
    projectId?: string | null;
    governing: SecurityGoverningScope;
    actorType: string;
    actorId: string;
    detail?: Record<string, string | number | boolean | null>;
  },
): Promise<SecurityProfile> {
  const { profile, row } = await resolveGoverning(db, ctx, rule);
  if (profile !== 'legacy') {
    try {
      await securityQueries(db).recordFinding({
        id: generateSecurityFindingId(),
        rule,
        profile,
        org_id: row?.org_id ?? ctx.orgId ?? null,
        project_id: ctx.projectId ?? null,
        actor_type: ctx.actorType,
        actor_id: ctx.actorId,
        detail: ctx.detail ?? {},
      });
    } catch {
      // A finding is evidence, not a control: never fail the work over it.
    }
  }
  return profile;
}

/**
 * `internal.service_key` for an internal-only service (worker, agent
 * runtime): decide a call that only the legacy internal key proves, and
 * record the finding. For `legacyInternalKeyJudge` in `@eve/shared`, which
 * caches the decision.
 */
export function internalLegacyKeyDecider(
  db: Db,
  callee: string,
): (path: string) => Promise<SecurityProfile> {
  return (path: string) =>
    decideSecurityRule(db, 'internal.service_key', {
      governing: 'instance',
      actorType: 'service',
      actorId: 'legacy-key',
      detail: { callee, route: path.slice(0, 120) },
    });
}
