import {
  BadRequestException,
  ForbiddenException,
  Inject,
  Injectable,
  Logger,
  NotFoundException,
} from '@nestjs/common';
import type { Db, SecurityProfileRow } from '@eve/db';
import { securityQueries, systemSettingsQueries } from '@eve/db';
import {
  SECURITY_NEW_PROJECT_PROFILE_SETTING,
  SECURITY_PROFILE_SETTING,
  generateSecurityFindingId,
  isSecurityProfile,
  resolveSecurityProfile,
  type SecurityGoverningScope,
  type SecurityProfile,
} from '@eve/shared';
import type { AuthUser } from '../auth/auth.types.js';

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

  constructor(@Inject('DB') db: Db) {
    this.settings = systemSettingsQueries(db);
    this.security = securityQueries(db);
  }

  /** The profile that governs a rule for this scope. */
  async effectiveProfile(scope: SecurityScope, governing: SecurityGoverningScope): Promise<SecurityProfile> {
    return (await this.resolve(scope, governing)).profile;
  }

  /**
   * Decide a rule without refusing: returns the governing profile and records
   * a finding under `audit` and `strict`. For callers that must do something
   * other than refuse (for example, mint a narrower token).
   */
  async decide(rule: string, ctx: SecurityGateContext): Promise<SecurityProfile> {
    const { profile, orgId } = await this.resolve(ctx, ctx.governing);
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

  async setProfile(
    target: SecurityProfileTarget,
    profile: SecurityProfile | null,
    actorUserId: string,
  ): Promise<{ scope: string; id: string | null; profile: SecurityProfile | null }> {
    if (profile !== null && !isSecurityProfile(profile)) {
      throw new BadRequestException(`Security profile must be legacy, audit or strict, not "${String(profile)}"`);
    }

    if (target.scope === 'instance' || target.scope === 'new_projects') {
      const key = target.scope === 'instance' ? SECURITY_PROFILE_SETTING : SECURITY_NEW_PROJECT_PROFILE_SETTING;
      if (profile === null) {
        await this.settings.delete(key);
      } else {
        await this.settings.set(key, profile, actorUserId);
      }
      this.settingCache.delete(key);
      return { scope: target.scope, id: null, profile };
    }

    if (!target.id) {
      throw new BadRequestException(`A ${target.scope} security profile needs the ${target.scope} id`);
    }
    const updated = target.scope === 'org'
      ? await this.security.setOrgProfile(target.id, profile)
      : await this.security.setProjectProfile(target.id, profile);
    if (!updated) {
      throw new NotFoundException(`${target.scope === 'org' ? 'Org' : 'Project'} ${target.id} not found`);
    }
    this.scopeCache.clear();
    return { scope: target.scope, id: target.id, profile };
  }

  /** Write the instance's profile for new projects onto a project just created. */
  async applyNewProjectProfile(projectId: string): Promise<void> {
    const value = await this.setting(SECURITY_NEW_PROJECT_PROFILE_SETTING);
    if (!isSecurityProfile(value)) return;
    await this.security.setProjectProfile(projectId, value);
    this.scopeCache.delete(`project:${projectId}`);
  }

  /** Profiles and findings for the instance, an org or a project. */
  async report(options: { orgId?: string; projectId?: string; days?: number }) {
    const days = Math.min(Math.max(Math.trunc(options.days ?? 14), 1), 90);
    const since = new Date(Date.now() - days * 24 * 60 * 60 * 1000);
    const instance = await this.setting(SECURITY_PROFILE_SETTING);
    const newProjects = await this.setting(SECURITY_NEW_PROJECT_PROFILE_SETTING);

    const projectRows = await this.security.listProjectProfiles({
      orgId: options.orgId,
      projectId: options.projectId,
    });
    const orgFilter = options.orgId ?? (options.projectId ? projectRows[0]?.org_id : undefined);
    const orgRows = await this.security.listOrgProfiles(orgFilter);
    const orgProfile = new Map(orgRows.map((o) => [o.id, o.security_profile]));

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

    return {
      days,
      instance_profile: resolveSecurityProfile({ instance }),
      new_project_profile: isSecurityProfile(newProjects) ? newProjects : null,
      orgs: orgRows.map((o) => ({
        id: o.id,
        slug: o.slug,
        profile: isSecurityProfile(o.security_profile) ? o.security_profile : null,
        effective: resolveSecurityProfile({ org: o.security_profile, instance }),
      })),
      projects: projectRows.map((p) => ({
        id: p.id,
        slug: p.slug,
        org_id: p.org_id ?? null,
        profile: isSecurityProfile(p.security_profile) ? p.security_profile : null,
        effective: resolveSecurityProfile({
          project: p.security_profile,
          org: p.org_id ? orgProfile.get(p.org_id) : null,
          instance,
        }),
      })),
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
  ): Promise<{ profile: SecurityProfile; orgId: string | null }> {
    const instance = await this.setting(SECURITY_PROFILE_SETTING);
    const row = scope.projectId || scope.orgId ? await this.scopeProfiles(scope) : null;
    const orgId = row?.org_id ?? scope.orgId ?? null;
    if (governing === 'instance') {
      return { profile: resolveSecurityProfile({ instance }), orgId };
    }
    return {
      profile: resolveSecurityProfile({
        project: governing === 'project' ? row?.project_profile : null,
        org: row?.org_profile,
        instance,
      }),
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
      await this.security.recordFinding({
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
