import { Inject, Injectable, Logger } from '@nestjs/common';
import {
  type Db,
  customDomainQueries,
  environmentQueries,
  ingressAliasQueries,
  orgQueries,
  projectQueries,
} from '@eve/db';
import { loadConfig, toK8sName, type SecurityProfile } from '@eve/shared';
import { SecurityService, type SecurityGateContext } from '../security/security.service.js';
import { AppAuthPolicyService } from './app-auth-policy.service.js';
import { AuthService } from './auth.service.js';
import { formatAppAudience } from './app-audience.js';
import { parseProjectAuthConfig } from './auth.util.js';
import type { AuthUser } from './auth.types.js';

/** Rules the instance profile governs for the SSO's /session and /logout. */
export const SSO_SESSION_ORIGIN_RULE = 'sso.session_origin';
export const SSO_AUDIENCE_TOKEN_RULE = 'sso.audience_token';
export const SSO_APP_ACCESS_RULE = 'sso.app_access';

export type SessionPurpose = 'session' | 'logout';

export interface SessionRequest {
  origin?: string | null;
  project_id?: string | null;
}

/** Who is asking the SSO, as judged from the request's Origin and project. */
type SessionCaller =
  | { kind: 'dashboard' }
  | { kind: 'sso' }
  | { kind: 'app'; projectId: string; orgId: string; audience: string }
  | { kind: 'refused'; reason: string; projectId: string | null; origin: string | null };

/** Custom-domain states in which the project has proved it holds the name. */
const VERIFIED_DOMAIN_STATES = new Set(['dns_verified', 'cert_provisioning', 'active']);

/**
 * What the SSO's /session and /logout may do (P1-2). The SSO asks before it
 * touches a session, and again for the token itself; the instance profile
 * decides, because the calling app is the party these rules guard against.
 *
 * - The Eve dashboard (no project) gets the platform token, as before.
 * - Any other caller names a project with `x-eve.auth` and calls from one of
 *   that project's own https hosts: its environments' default hosts, its
 *   ingress aliases, its verified custom domains, and its manifest
 *   `allowed_redirect_origins`. Other orgs' domains never count.
 * - Under `strict` such an app gets an audience token, and only for a person
 *   its app-access policy admits. Under `audit` it gets today's token and the
 *   difference is recorded.
 */
@Injectable()
export class SsoSessionService {
  private readonly logger = new Logger(SsoSessionService.name);
  private readonly projects: ReturnType<typeof projectQueries>;
  private readonly orgs: ReturnType<typeof orgQueries>;
  private readonly environments: ReturnType<typeof environmentQueries>;
  private readonly aliases: ReturnType<typeof ingressAliasQueries>;
  private readonly domains: ReturnType<typeof customDomainQueries>;

  constructor(
    @Inject('DB') db: Db,
    private readonly authService: AuthService,
    private readonly appAuthPolicy: AppAuthPolicyService,
    private readonly security: SecurityService,
  ) {
    this.projects = projectQueries(db);
    this.orgs = orgQueries(db);
    this.environments = environmentQueries(db);
    this.aliases = ingressAliasQueries(db);
    this.domains = customDomainQueries(db);
  }

  /**
   * May this Origin use /session or /logout? Returns the instance profile so
   * the SSO keeps today's rules under `legacy` and `audit`, and whether the
   * origin meets this rule. An origin that does not is recorded.
   */
  async checkOrigin(input: SessionRequest & { purpose: SessionPurpose }): Promise<{ profile: SecurityProfile; allowed: boolean }> {
    const caller = await this.identifyCaller(input, input.purpose);
    if (caller.kind !== 'refused') {
      return { profile: await this.security.effectiveProfile({}, 'instance'), allowed: true };
    }
    // This route is public: the finding names an origin only for a project
    // that exists, and keeps the detail the day's row was first written with.
    const profile = await this.security.decide(SSO_SESSION_ORIGIN_RULE, {
      ...this.refusalContext(caller, input.purpose, null),
      keepFirstDetail: true,
    });
    return { profile, allowed: false };
  }

  /**
   * The token /session hands to the caller, for the person signed in to
   * GoTrue. Throws 403 where the strict profile refuses.
   */
  async issueSessionToken(
    supabaseToken: string,
    input: SessionRequest,
  ): Promise<{ access_token: string; token_type: string; expires_at: number; user_id: string; audience?: string }> {
    const user = await this.authService.resolveSupabaseTokenForExchange(supabaseToken);
    const caller = await this.identifyCaller(input, 'session');

    if (caller.kind === 'refused') {
      await this.security.gate(
        SSO_SESSION_ORIGIN_RULE,
        this.refusalContext(caller, 'session', user),
        'This origin may not ask for a session',
      );
      return this.platformToken(user);
    }
    if (caller.kind !== 'app') {
      return this.platformToken(user);
    }

    const access = await this.appAuthPolicy.getUserAppAccess(caller.projectId, user.user_id);
    const scope = { governing: 'instance' as const, orgId: caller.orgId, projectId: caller.projectId, actor: user };
    if (access.orgs.length === 0) {
      await this.security.gate(SSO_APP_ACCESS_RULE, scope, "This app's access policy does not admit you");
    }

    const profile = await this.security.decide(SSO_AUDIENCE_TOKEN_RULE, { ...scope, detail: { audience: caller.audience } });
    if (profile !== 'strict') {
      return this.platformToken(user);
    }
    const token = await this.authService.mintAppUserToken(user.user_id, user.email, caller.audience);
    return { ...token, user_id: user.user_id, audience: caller.audience };
  }

  private async platformToken(user: AuthUser) {
    const token = await this.authService.mintUserToken(user.user_id, user.email);
    return { ...token, user_id: user.user_id };
  }

  private refusalContext(
    caller: Extract<SessionCaller, { kind: 'refused' }>,
    purpose: SessionPurpose,
    actor: AuthUser | null,
  ): SecurityGateContext {
    return {
      governing: 'instance',
      projectId: caller.projectId,
      actor,
      detail: {
        purpose,
        reason: caller.reason,
        // An origin is recorded only against a project that exists.
        ...(caller.projectId ? { origin: caller.origin } : {}),
      },
    };
  }

  private async identifyCaller(input: SessionRequest, purpose: SessionPurpose): Promise<SessionCaller> {
    const projectId = input.project_id || null;
    const origin = input.origin || null;
    // A finding names the project only once it is known to exist, so these
    // public checks cannot add rows for made-up ids.
    let knownProjectId: string | null = null;
    const refused = (reason: string): SessionCaller => ({
      kind: 'refused',
      reason,
      projectId: knownProjectId,
      origin: origin ? origin.slice(0, 200) : null,
    });

    if (!origin) return refused('no_origin');
    let parsed: URL;
    try {
      parsed = new URL(origin);
    } catch {
      return refused('bad_origin');
    }
    if (parsed.origin !== origin) return refused('bad_origin');

    const config = loadConfig();
    if (purpose === 'logout' && origin === originOf(config.EVE_SSO_URL)) return { kind: 'sso' };
    if (!projectId) {
      return origin === dashboardOrigin(config) ? { kind: 'dashboard' } : refused('no_project');
    }

    // Plain http only where the SSO itself is plain http (a local cluster).
    const ssoProtocol = config.EVE_SSO_URL ? new URL(config.EVE_SSO_URL).protocol : 'https:';
    if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && ssoProtocol === 'http:')) {
      return refused('insecure_origin');
    }

    const project = await this.projects.findById(projectId, { include_deleted: false });
    if (!project) return refused('unknown_project');
    knownProjectId = project.id;
    const auth = parseProjectAuthConfig(this.logger, project.auth_config);
    if (!auth) return refused('no_app_auth');

    const envName = await this.projectHostEnvironment(project, auth.allowed_redirect_origins ?? [], parsed, config.EVE_DEFAULT_DOMAIN);
    if (envName === undefined) return refused('not_a_project_host');
    return { kind: 'app', projectId: project.id, orgId: project.org_id, audience: formatAppAudience(project.id, envName) };
  }

  /**
   * The environment a host of this project serves (null when its address
   * names none), or undefined when the origin is not one of the project's.
   */
  private async projectHostEnvironment(
    project: { id: string; org_id: string; slug: string },
    manifestOrigins: string[],
    origin: URL,
    defaultDomain: string | undefined,
  ): Promise<string | null | undefined> {
    const environments = await this.environments.listByProject(project.id);
    const envName = (environmentId: string | null) =>
      environments.find((env) => env.id === environmentId)?.name ?? null;
    const host = origin.hostname.toLowerCase();
    const standardPort = origin.port === '';

    if (defaultDomain && standardPort) {
      const domain = defaultDomain.toLowerCase();
      const org = await this.orgs.findById(project.org_id, { include_deleted: false });
      if (org) {
        // Default hosts: {component}.{org}-{project}-{env}.{domain}
        for (const env of environments) {
          const suffix = `.${toK8sName(org.slug, 'org')}-${toK8sName(project.slug, 'project')}-${toK8sName(env.name, 'environment')}.${domain}`;
          if (host.endsWith(suffix) && isSingleLabel(host.slice(0, -suffix.length))) return env.name;
        }
      }
      for (const alias of await this.aliases.findByProject(project.id)) {
        if (host === `${alias.alias}.${domain}`) return envName(alias.environment_id);
      }
    }

    if (standardPort) {
      for (const domain of await this.domains.findByProject(project.id)) {
        if (domain.hostname.toLowerCase() === host && VERIFIED_DOMAIN_STATES.has(domain.status)) {
          return envName(domain.environment_id);
        }
      }
    }

    if (manifestOrigins.some((entry) => originOf(entry) === origin.origin)) return null;
    return undefined;
  }
}

function originOf(url: string | undefined): string | null {
  if (!url) return null;
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

/** The Eve dashboard's origin: EVE_DASHBOARD_URL, else the SSO URL with `sso.` read as `dashboard.`. */
function dashboardOrigin(config: { EVE_DASHBOARD_URL?: string; EVE_SSO_URL?: string }): string | null {
  const explicit = originOf(config.EVE_DASHBOARD_URL);
  if (explicit) return explicit;
  const sso = config.EVE_SSO_URL ? new URL(config.EVE_SSO_URL) : null;
  if (!sso || !sso.hostname.startsWith('sso.')) return null;
  return `${sso.protocol}//dashboard.${sso.hostname.slice('sso.'.length)}${sso.port ? `:${sso.port}` : ''}`;
}

function isSingleLabel(value: string): boolean {
  return /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(value);
}
