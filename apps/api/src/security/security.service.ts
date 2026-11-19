import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import type { Db, SecurityProfileRow } from '@eve/db';
import { auditQueries, securityQueries, systemSettingsQueries } from '@eve/db';
import {
  SECURITY_CURRENT_RULESET,
  SECURITY_NEW_PROJECT_PROFILE_SETTING,
  SECURITY_PROFILE_RULESET_SETTING,
  SECURITY_PROFILE_SETTING,
  generateSecurityFindingId,
  governingSecurityLevel,
  isSecurityProfile,
  parseSecurityRuleset,
  resolveSecurityProfile,
  type SecurityGoverningScope,
  type SecurityProfile,
  type SecurityProfileLevels,
} from '@eve/shared';
import type { AuthUser } from '../auth/auth.types.js';
import { countStoredCredentials, legacyCredentialRows } from '../secrets/credential-storage.js';

export interface SecurityScope {
  orgId?: string | null;
  projectId?: string | null;
}

export interface SecurityGateContext extends SecurityScope {
  /** Whose profile decides: the side the rule protects. */
  governing: SecurityGoverningScope;
  actor?: AuthUser | null;
  /** Names and ids only; never a secret, token, value or request body. */
  detail?: Record<string, string | number | boolean | null>;
  /**
   * Keep the detail the day's row was first written with (findings an
   * unauthenticated caller can cause).
   */
  keepFirstDetail?: boolean;
}

export type SecurityProfileTarget =
  | { scope: 'instance' | 'new_projects'; id?: undefined }
  | { scope: 'org' | 'project'; id?: string };

/** Profiles are cached briefly per process; a change made here is seen at once. */
const PROFILE_CACHE_MS = 30_000;
/** A repeat finding (same rule, scope and actor) is written at most hourly per process. */
const RECORD_INTERVAL_MS = 60 * 60 * 1000;
const MAX_RECORD_KEYS = 10_000;

@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);
  private readonly settings: ReturnType<typeof systemSettingsQueries>;
  private readonly security: ReturnType<typeof securityQueries>;
  private readonly settingCache = new Map<string, { value: string | null; at: number }>();
  private readonly scopeCache = new Map<string, { row: SecurityProfileRow; at: number }>();
  private readonly recorded = new Map<string, number>();

  constructor(@Inject('DB') private readonly db: Db) {
    this.settings = systemSettingsQueries(db);
    this.security = securityQueries(db);
  }

  /**
   * The profile that governs a rule for this scope. With the rule, a
   * `strict` stamped before the rule's rule set gives `audit`; without it,
   * the rule set is 1.
   */
  async effectiveProfile(
    scope: SecurityScope,
    governing: SecurityGoverningScope,
    rule?: string,
  ): Promise<SecurityProfile> {
    return (await this.resolve(scope, governing, rule)).profile;
  }

  /**
   * Decide a rule without refusing: returns the governing profile and records
   * a finding under `audit` and `strict`. For callers that must do something
   * other than refuse (for example, mint a narrower token).
   */
  async decide(rule: string, ctx: SecurityGateContext): Promise<SecurityProfile> {
    const { profile, orgId } = await this.resolve(ctx, ctx.governing, rule);
    if (profile !== 'legacy') {
      await this.record(rule, profile, orgId, ctx);
    }
    return profile;
  }

  /**
   * Apply a rule that `strict` enforces by refusing. Call it only where the
   * request would break the rule. `legacy` allows silently, `audit` allows and
   * records, `strict` records and refuses with 403.
   */
  async gate(rule: string, ctx: SecurityGateContext, message?: string): Promise<'allowed' | 'recorded'> {
    const profile = await this.decide(rule, ctx);
    if (profile === 'legacy') return 'allowed';
    if (profile === 'strict') {
      throw new ForbiddenException(`${message ?? 'Refused by the security profile'} (rule ${rule})`);
    }
    return 'recorded';
  }

  /**
   * Set a profile. The instance goes `strict` only once no v1 secret or
   * plain OAuth column is left (its `secrets.legacy_ciphertext` would refuse
   * them): 409 otherwise, unless `force`.
   */
  async setProfile(
    target: SecurityProfileTarget,
    profile: SecurityProfile | null,
    actorUserId: string,
    options: { force?: boolean } = {},
  ): Promise<{ scope: string; id: string | null; profile: SecurityProfile | null; ruleset: number | null }> {
    if (profile !== null && !isSecurityProfile(profile)) {
      throw new BadRequestException(`Security profile must be legacy, audit or strict, not "${String(profile)}"`);
    }

    if ((target.scope === 'org' || target.scope === 'project') && !target.id) {
      throw new BadRequestException(`A ${target.scope} security profile needs the ${target.scope} id`);
    }
    // A strict profile covers the rules of the current rule set; any other
    // profile carries no stamp.
    const ruleset = profile === 'strict' ? SECURITY_CURRENT_RULESET : null;
    // The change and its audit record commit together, or neither does.
    const result = await this.db.begin(async (rawTx) => {
      const tx = rawTx as unknown as Db;
      const settings = systemSettingsQueries(tx);
      const security = securityQueries(tx);
      const audit = auditQueries(tx);

      if (target.scope === 'instance' || target.scope === 'new_projects') {
        let forcedWithLegacy = 0;
        if (target.scope === 'instance' && profile === 'strict') {
          const legacy = legacyCredentialRows(await countStoredCredentials(tx));
          if (legacy > 0 && !options.force) {
            throw new ConflictException(
              `${legacy} credential(s) are still stored as v1 secrets or plain OAuth columns, which a strict instance refuses. ` +
              'Run eve system secrets reencrypt first (--dry-run shows them), or set the instance strict with --force.',
            );
          }
          forcedWithLegacy = legacy;
        }
        const key = target.scope === 'instance' ? SECURITY_PROFILE_SETTING : SECURITY_NEW_PROJECT_PROFILE_SETTING;
        const previous = (await settings.get(key))?.value ?? null;
        // Clearing the instance profile leaves it unset, which resolves to legacy.
        if (profile === null) {
          await settings.delete(key);
        } else {
          await settings.set(key, profile, actorUserId);
        }
        // New projects are stamped as they are created (applyNewProjectProfile).
        if (target.scope === 'instance') {
          if (ruleset === null) {
            await settings.delete(SECURITY_PROFILE_RULESET_SETTING);
          } else {
            await settings.set(SECURITY_PROFILE_RULESET_SETTING, String(ruleset), actorUserId);
          }
        }
        await recordProfileChange(audit, target.scope, previous, profile, actorUserId, target.scope === 'instance' ? ruleset : null, {
          ...(forcedWithLegacy > 0 ? { forced_with_legacy_credentials: forcedWithLegacy } : {}),
        });
        return { scope: target.scope, id: null, profile, ruleset: target.scope === 'instance' ? ruleset : null };
      }

      const id = target.id!;
      const before = target.scope === 'org'
        ? await security.getProfiles({ orgId: id })
        : await security.getProfiles({ projectId: id });
      const previous = target.scope === 'org' ? before.org_profile : before.project_profile;
      const updated = target.scope === 'org'
        ? await security.setOrgProfile(id, profile, ruleset)
        : await security.setProjectProfile(id, profile, ruleset);
      if (!updated) {
        throw new NotFoundException(`${target.scope === 'org' ? 'Org' : 'Project'} ${id} not found`);
      }
      await recordProfileChange(audit, `${target.scope}:${id}`, previous, profile, actorUserId, ruleset);
      return { scope: target.scope, id, profile, ruleset };
    });
    if (result.id === null) {
      this.settingCache.delete(target.scope === 'instance' ? SECURITY_PROFILE_SETTING : SECURITY_NEW_PROJECT_PROFILE_SETTING);
      this.settingCache.delete(SECURITY_PROFILE_RULESET_SETTING);
    } else {
      this.scopeCache.clear();
    }
    return result;
  }

  /**
   * Write the instance's profile for new projects onto a project just
   * created; a `strict` is stamped with the current rule set.
   */
  async applyNewProjectProfile(projectId: string): Promise<void> {
    const value = await this.setting(SECURITY_NEW_PROJECT_PROFILE_SETTING);
    if (!isSecurityProfile(value)) return;
    await this.security.setProjectProfile(projectId, value, value === 'strict' ? SECURITY_CURRENT_RULESET : null);
    this.scopeCache.delete(`project:${projectId}`);
  }

  /** Profiles and findings for the instance, an org or a project. */
  async report(options: { orgId?: string; projectId?: string; days?: number }) {
    const days = Math.min(Math.max(Math.trunc(options.days ?? 14), 1), 90);
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const instance = await this.setting(SECURITY_PROFILE_SETTING);
    const instanceRuleset = await this.setting(SECURITY_PROFILE_RULESET_SETTING);
    const newProjects = await this.setting(SECURITY_NEW_PROJECT_PROFILE_SETTING);

    const projectRows = await this.security.listProjectProfiles({
      orgId: options.orgId,
      projectId: options.projectId,
    });
    const orgFilter = options.orgId ?? (options.projectId ? projectRows[0]?.org_id : undefined);
    const orgRows = await this.security.listOrgProfiles(orgFilter);
    const orgById = new Map(orgRows.map((o) => [o.id, o]));

    const findings = await this.security.listFindings({
      since,
      orgId: options.projectId ? undefined : options.orgId,
      projectId: options.projectId,
    });
    const byRule = new Map<string, { rule: string; count: number; projects: Set<string>; actors: Set<string> }>();
    for (const f of findings) {
      const entry = byRule.get(f.rule) ?? { rule: f.rule, count: 0, projects: new Set(), actors: new Set() };
      entry.count += f.count;
      if (f.project_id) entry.projects.add(f.project_id);
      entry.actors.add(`${f.actor_type}:${f.actor_id}`);
      byRule.set(f.rule, entry);
    }

    const own = (profile: string | null, stamp: number | null | undefined) => ({
      profile: isSecurityProfile(profile) ? profile : null,
      ruleset: profile === 'strict' ? parseSecurityRuleset(stamp) : null,
    });
    const effective = (levels: SecurityProfileLevels) => {
      const level = governingSecurityLevel(levels);
      return { effective: level.profile, effective_ruleset: level.ruleset };
    };
    const instanceLevel = governingSecurityLevel({ instance, instanceRuleset });

    return {
      days,
      current_ruleset: SECURITY_CURRENT_RULESET,
      instance_profile: instanceLevel.profile,
      instance_ruleset: instanceLevel.ruleset,
      new_project_profile: isSecurityProfile(newProjects) ? newProjects : null,
      orgs: orgRows.map((o) => ({
        id: o.id,
        slug: o.slug,
        ...own(o.security_profile, o.security_profile_ruleset),
        ...effective({ org: o.security_profile, orgRuleset: o.security_profile_ruleset, instance, instanceRuleset }),
      })),
      projects: projectRows.map((p) => {
        const org = p.org_id ? orgById.get(p.org_id) : undefined;
        return {
          id: p.id,
          slug: p.slug,
          org_id: p.org_id ?? null,
          ...own(p.security_profile, p.security_profile_ruleset),
          ...effective({
            project: p.security_profile,
            projectRuleset: p.security_profile_ruleset,
            org: org?.security_profile,
            orgRuleset: org?.security_profile_ruleset,
            instance,
            instanceRuleset,
          }),
        };
      }),
      summary: [...byRule.values()]
        .map((r) => ({ rule: r.rule, count: r.count, projects: r.projects.size, actors: r.actors.size }))
        .sort((a, b) => b.count - a.count),
      findings: findings.map((f) => ({
        rule: f.rule,
        profile: f.profile,
        org_id: f.org_id,
        project_id: f.project_id,
        actor_type: f.actor_type,
        actor_id: f.actor_id,
        detail: f.detail,
        count: f.count,
        first_seen: f.first_seen,
        last_seen: f.last_seen,
      })),
    };
  }

  private async resolve(
    scope: SecurityScope,
    governing: SecurityGoverningScope,
    rule?: string,
  ): Promise<{ profile: SecurityProfile; orgId: string | null }> {
    const instance = await this.setting(SECURITY_PROFILE_SETTING);
    const instanceRuleset = await this.setting(SECURITY_PROFILE_RULESET_SETTING);
    const row = scope.projectId || scope.orgId ? await this.scopeProfiles(scope) : null;
    const orgId = row?.org_id ?? scope.orgId ?? null;
    if (governing === 'instance') {
      return { profile: resolveSecurityProfile({ instance, instanceRuleset }, rule), orgId };
    }
    return {
      profile: resolveSecurityProfile({
        project: governing === 'project' ? row?.project_profile : null,
        projectRuleset: governing === 'project' ? row?.project_ruleset : null,
        org: row?.org_profile,
        orgRuleset: row?.org_ruleset,
        instance,
        instanceRuleset,
      }, rule),
      orgId,
    };
  }

  private async setting(key: string): Promise<string | null> {
    const cached = this.settingCache.get(key);
    if (cached && Date.now() - cached.at < PROFILE_CACHE_MS) return cached.value;
    const row = await this.settings.get(key);
    const value = row?.value ?? null;
    this.settingCache.set(key, { value, at: Date.now() });
    return value;
  }

  private async scopeProfiles(scope: SecurityScope): Promise<SecurityProfileRow> {
    const key = scope.projectId ? `project:${scope.projectId}` : `org:${scope.orgId}`;
    const cached = this.scopeCache.get(key);
    if (cached && Date.now() - cached.at < PROFILE_CACHE_MS) return cached.row;
    const row = await this.security.getProfiles(scope);
    this.scopeCache.set(key, { row, at: Date.now() });
    return row;
  }

  private async record(
    rule: string,
    profile: SecurityProfile,
    orgId: string | null,
    ctx: SecurityGateContext,
  ): Promise<void> {
    const [actorType, actorId] = describeActor(ctx.actor);
    const day = new Date().toISOString().slice(0, 10);
    const key = [rule, profile, orgId ?? '', ctx.projectId ?? '', actorType, actorId, day].join('|');
    const now = Date.now();
    const last = this.recorded.get(key);
    if (last !== undefined && now - last < RECORD_INTERVAL_MS) return;
    if (this.recorded.size >= MAX_RECORD_KEYS) this.recorded.clear();
    this.recorded.set(key, now);
    try {
      const write = ctx.keepFirstDetail ? this.security.recordFindingKeepingDetail : this.security.recordFinding;
      await write({
        id: generateSecurityFindingId(),
        rule,
        profile,
        org_id: orgId,
        project_id: ctx.projectId ?? null,
        actor_type: actorType,
        actor_id: actorId,
        detail: ctx.detail ?? {},
      });
    } catch (error) {
      // A finding is evidence, not a control: never fail the request over it.
      this.logger.warn(`Could not record security finding ${rule}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }
}

/** What kind of principal acted, and its id, for a finding. */
export function describeActor(actor: AuthUser | null | undefined): [string, string] {
  if (!actor) return ['none', 'none'];
  if (actor.is_job_token) return ['job', actor.job_id ?? actor.user_id];
  if (actor.is_service_token) return ['service', actor.service_name ?? actor.user_id];
  if (actor.is_service_principal) return ['service_principal', actor.user_id];
  if (actor.is_app_link_token) return ['app_link', actor.subscription_id ?? actor.user_id];
  return ['user', actor.user_id];
}

/** Who changed a profile, from what to what, and the rule set a strict covers: an audit log entry. */
async function recordProfileChange(
  audit: ReturnType<typeof auditQueries>,
  entityId: string,
  previous: string | null,
  profile: string | null,
  actorUserId: string,
  ruleset: number | null,
  extra: Record<string, number> = {},
): Promise<void> {
  await audit.log({
    entity_type: 'security_profile',
    entity_id: entityId,
    action: 'updated',
    actor: actorUserId,
    actor_type: 'user',
    changes: { profile: { old: previous, new: profile } },
    context: { ...(ruleset === null ? {} : { ruleset }), ...extra },
  });
}
