import { generateKeyPairSync } from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { SsoSessionService } from './sso-session.service';
import { AuthService } from './auth.service';
import { AppAuthService } from './app-auth.service';
import { AppAuthPolicyService } from './app-auth-policy.service';
import { MagicLinkService } from './magic-link.service';
import { TokenVerifierService } from './token-verifier.service';
import { BootstrapService } from './bootstrap.service';
import { SecurityService } from '../security/security.service';
import type { MailerService } from '../mailer/mailer.service';
import type { IdentityProviderRegistry } from './providers/index.js';

/**
 * What the SSO's /session and /logout may do, decided by the API under the
 * instance security profile: which origins may ask, and what token an app
 * gets.
 */

const DOMAIN = 'apps.eve.example';
const SSO = 'https://sso.eve.example';
const DASHBOARD = 'https://dashboard.eve.example';

const state = vi.hoisted(() => ({
  settings: new Map<string, string>(),
  findings: [] as Array<{ rule: string; profile: string; project_id: string | null; actor_type: string; actor_id: string; detail: Record<string, unknown> }>,
  orgs: [] as Array<{ id: string; slug: string; name: string }>,
  projects: [] as Array<{ id: string; org_id: string; slug: string; name: string; auth_config: Record<string, unknown> | null; branding: null; deleted_at: null }>,
  environments: [] as Array<{ id: string; project_id: string; name: string }>,
  aliases: [] as Array<{ alias: string; project_id: string; environment_id: string | null }>,
  domains: [] as Array<{ hostname: string; project_id: string; environment_id: string | null; status: string }>,
  users: [] as Array<{ id: string; email: string; is_admin: boolean; display_name: null }>,
  memberships: [] as Array<{ org_id: string; user_id: string; role: 'owner' | 'admin' | 'member'; created_at: Date }>,
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const byProject = <T extends { project_id: string }>(rows: T[]) => async (projectId: string) =>
    rows.filter((row) => row.project_id === projectId);
  return {
    ...actual,
    systemSettingsQueries: vi.fn(() => ({
      get: vi.fn(async (key: string) => (state.settings.has(key) ? { key, value: state.settings.get(key) } : null)),
    })),
    securityQueries: vi.fn(() => ({
      getProfiles: vi.fn(async () => ({ org_id: null, org_profile: null, project_profile: null })),
      recordFinding: vi.fn(async (finding: (typeof state.findings)[number]) => {
        state.findings.push(finding);
      }),
    })),
    orgQueries: vi.fn(() => ({
      findById: vi.fn(async (id: string) => state.orgs.find((o) => o.id === id) ?? null),
      findBySlug: vi.fn(async (slug: string) => state.orgs.find((o) => o.slug === slug) ?? null),
    })),
    projectQueries: vi.fn(() => ({
      findById: vi.fn(async (id: string) => state.projects.find((p) => p.id === id) ?? null),
    })),
    environmentQueries: vi.fn(() => ({
      listByProject: vi.fn(async (projectId: string) => state.environments.filter((e) => e.project_id === projectId)),
    })),
    ingressAliasQueries: vi.fn(() => ({ findByProject: vi.fn(byProject(state.aliases)) })),
    customDomainQueries: vi.fn(() => ({
      findByProject: vi.fn(async (projectId: string) =>
        state.domains.filter((d) => d.project_id === projectId && d.status !== 'removed')),
      findRedirectEligibleByProjectIds: vi.fn(async (ids: string[]) =>
        state.domains.filter((d) => ids.includes(d.project_id) && d.environment_id)),
      findRedirectEligibleByOrgIds: vi.fn(async (orgIds: string[]) =>
        state.domains.filter((d) => d.environment_id
          && orgIds.includes(state.projects.find((p) => p.id === d.project_id)?.org_id ?? ''))),
    })),
    userQueries: vi.fn(() => ({
      findById: vi.fn(async (id: string) => state.users.find((u) => u.id === id) ?? null),
      findByEmail: vi.fn(async (email: string) => state.users.find((u) => u.email === email) ?? null),
    })),
    membershipQueries: vi.fn(() => ({
      listOrgMembershipsForUser: vi.fn(async (userId: string) => state.memberships.filter((m) => m.user_id === userId)),
      findOrgMembership: vi.fn(async (userId: string, orgId: string) =>
        state.memberships.find((m) => m.user_id === userId && m.org_id === orgId) ?? null),
    })),
  };
});

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

/** The org rows the policy service and verifier load with raw SQL. */
const db = vi.fn(async (_strings: TemplateStringsArray, ...values: unknown[]) => {
  const ids = values.find(Array.isArray) as string[] | undefined;
  return ids ? state.orgs.filter((o) => ids.includes(o.id)) : [];
});

function decode(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1] ?? '', 'base64url').toString('utf8')) as Record<string, unknown>;
}

function build(profile: 'legacy' | 'audit' | 'strict') {
  state.settings.set('security.profile', profile);
  const mailer = { send: vi.fn() } as unknown as MailerService;
  const magicLink = new MagicLinkService(db as never, mailer);
  const policy = new AppAuthPolicyService(db as never);
  const appAuth = new AppAuthService(db as never, magicLink, policy);
  const verifier = new TokenVerifierService(db as never, appAuth, magicLink);
  const bootstrap = new BootstrapService(db as never, appAuth);
  const authService = new AuthService(
    db as never,
    {} as IdentityProviderRegistry,
    magicLink,
    appAuth,
    verifier,
    bootstrap,
    policy,
  );
  const security = new SecurityService(db as never);
  const service = new SsoSessionService(db as never, authService, policy, security);
  return { service, authService };
}

/** Sign in as this user: the GoTrue token is resolved to them. */
function signInAs(authService: AuthService, userId: string): void {
  const user = state.users.find((u) => u.id === userId);
  vi.spyOn(authService, 'resolveSupabaseTokenForExchange').mockResolvedValue({
    user_id: userId,
    email: user?.email,
  });
}

const SHOP = 'proj_shop';
const ALIAS_ORIGIN = `https://shop.${DOMAIN}`;

beforeEach(() => {
  vi.clearAllMocks();
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  process.env.EVE_AUTH_ENABLED = 'true';
  process.env.EVE_AUTH_PRIVATE_KEY = privatePem;
  process.env.EVE_SSO_URL = SSO;
  process.env.EVE_DASHBOARD_URL = DASHBOARD;
  process.env.EVE_DEFAULT_DOMAIN = DOMAIN;

  state.settings = new Map();
  state.findings = [];
  state.orgs = [
    { id: 'org_acme', slug: 'acme', name: 'ACME' },
    { id: 'org_b', slug: 'borg', name: 'B' },
  ];
  state.projects = [
    {
      id: SHOP,
      org_id: 'org_acme',
      slug: 'shop',
      name: 'shop',
      // An allowlist app naming another org: that org's domains are still not this app's.
      auth_config: {
        org_access: { mode: 'allowlist', allowed_orgs: ['org_acme', 'org_b'] },
        allowed_redirect_origins: ['https://shop.partner.example'],
      },
      branding: null,
      deleted_at: null,
    },
    { id: 'proj_other', org_id: 'org_acme', slug: 'other', name: 'other', auth_config: {}, branding: null, deleted_at: null },
    { id: 'proj_b', org_id: 'org_b', slug: 'portal', name: 'portal', auth_config: {}, branding: null, deleted_at: null },
    { id: 'proj_plain', org_id: 'org_acme', slug: 'plain', name: 'plain', auth_config: null, branding: null, deleted_at: null },
  ];
  state.environments = [
    { id: 'env_shop_prod', project_id: SHOP, name: 'prod' },
    { id: 'env_shop_staging', project_id: SHOP, name: 'staging' },
    { id: 'env_other_prod', project_id: 'proj_other', name: 'prod' },
    { id: 'env_plain_prod', project_id: 'proj_plain', name: 'prod' },
  ];
  state.aliases = [{ alias: 'shop', project_id: SHOP, environment_id: 'env_shop_prod' }];
  state.domains = [
    { hostname: 'shop.acme.example', project_id: SHOP, environment_id: null, status: 'active' },
    { hostname: 'pending.acme.example', project_id: SHOP, environment_id: 'env_shop_prod', status: 'pending_dns' },
    { hostname: 'portal.b.example', project_id: 'proj_b', environment_id: 'env_b', status: 'active' },
  ];
  state.users = [
    { id: 'user_member', email: 'member@acme.example', is_admin: false, display_name: null },
    { id: 'user_outsider', email: 'outsider@example.com', is_admin: false, display_name: null },
  ];
  state.memberships = [{ org_id: 'org_acme', user_id: 'user_member', role: 'member', created_at: new Date() }];
});

describe('SsoSessionService.checkOrigin under the strict instance profile', () => {
  const check = (origin: string | null, projectId: string | null, purpose: 'session' | 'logout' = 'session') =>
    build('strict').service.checkOrigin({ origin, project_id: projectId, purpose });

  it.each([
    ['no Origin', null, SHOP],
    ['no Origin and no project', null, null],
    ["another project's default host", `https://web.acme-other-prod.${DOMAIN}`, SHOP],
    ["another org's verified custom domain, though the app's sign-in names that org", 'https://portal.b.example', SHOP],
    ['an unverified custom domain', 'https://pending.acme.example', SHOP],
    ['a plain http origin', `http://shop.${DOMAIN}`, SHOP],
    ['the dashboard origin naming a project', DASHBOARD, SHOP],
    ['an app host with no project named', ALIAS_ORIGIN, null],
    ['a project without x-eve.auth', `https://web.acme-plain-prod.${DOMAIN}`, 'proj_plain'],
    ['the SSO itself asking for a session', SSO, null],
    ['an unknown project', ALIAS_ORIGIN, 'proj_missing'],
  ])('refuses %s', async (_label, origin, projectId) => {
    await expect(check(origin, projectId)).resolves.toEqual({ profile: 'strict', allowed: false });
  });

  it.each([
    ['the dashboard, with no project', DASHBOARD, null],
    ['an ingress alias of the project', ALIAS_ORIGIN, SHOP],
    ['a default host of one of its environments', `https://web.acme-shop-staging.${DOMAIN}`, SHOP],
    ['a verified custom domain of the project', 'https://shop.acme.example', SHOP],
    ['a manifest allowed_redirect_origins entry', 'https://shop.partner.example', SHOP],
  ])('allows %s', async (_label, origin, projectId) => {
    await expect(check(origin, projectId)).resolves.toEqual({ profile: 'strict', allowed: true });
  });

  it('allows the SSO origin to sign out, with or without a project', async () => {
    await expect(check(SSO, null, 'logout')).resolves.toEqual({ profile: 'strict', allowed: true });
    await expect(check(SSO, SHOP, 'logout')).resolves.toEqual({ profile: 'strict', allowed: true });
  });

  it('applies the same origins to sign-out as to sessions', async () => {
    await expect(check(null, null, 'logout')).resolves.toEqual({ profile: 'strict', allowed: false });
    await expect(check(ALIAS_ORIGIN, SHOP, 'logout')).resolves.toEqual({ profile: 'strict', allowed: true });
  });

  it('records each refusal as a finding', async () => {
    await check(`https://web.acme-other-prod.${DOMAIN}`, SHOP);
    expect(state.findings).toEqual([
      expect.objectContaining({ rule: 'sso.session_origin', profile: 'strict', project_id: SHOP }),
    ]);
  });
});

describe('SsoSessionService.checkOrigin under audit and legacy', () => {
  it('under audit, reports the profile and records an origin strict would refuse', async () => {
    const { service } = build('audit');
    await expect(service.checkOrigin({ origin: null, project_id: SHOP, purpose: 'session' }))
      .resolves.toEqual({ profile: 'audit', allowed: false });
    expect(state.findings.map((f) => f.rule)).toEqual(['sso.session_origin']);
  });

  it('under audit, records nothing for an origin strict allows', async () => {
    const { service } = build('audit');
    await service.checkOrigin({ origin: ALIAS_ORIGIN, project_id: SHOP, purpose: 'session' });
    expect(state.findings).toEqual([]);
  });

  it('under legacy, records nothing', async () => {
    const { service } = build('legacy');
    await expect(service.checkOrigin({ origin: null, project_id: SHOP, purpose: 'session' }))
      .resolves.toEqual({ profile: 'legacy', allowed: false });
    expect(state.findings).toEqual([]);
  });
});

describe('SsoSessionService.issueSessionToken', () => {
  describe('under the strict instance profile', () => {
    it('gives an app on its alias a one-hour audience token with no orgs claim', async () => {
      const { service, authService } = build('strict');
      signInAs(authService, 'user_member');

      const issued = await service.issueSessionToken('gotrue-token', { origin: ALIAS_ORIGIN, project_id: SHOP });

      const claims = decode(issued.access_token);
      expect(claims).toMatchObject({ sub: 'user_member', type: 'user', aud: `eve-app:${SHOP}:prod` });
      expect(claims).not.toHaveProperty('orgs');
      expect(Number(claims.exp) - Number(claims.iat)).toBe(3600);
      expect(issued).toMatchObject({ user_id: 'user_member', audience: `eve-app:${SHOP}:prod` });
    });

    it('names no environment for an origin that has none', async () => {
      const { service, authService } = build('strict');
      signInAs(authService, 'user_member');

      const issued = await service.issueSessionToken('gotrue-token', {
        origin: 'https://shop.partner.example',
        project_id: SHOP,
      });

      expect(decode(issued.access_token).aud).toBe(`eve-app:${SHOP}`);
    });

    it("refuses a visitor the app's access policy does not admit", async () => {
      const { service, authService } = build('strict');
      signInAs(authService, 'user_outsider');

      await expect(
        service.issueSessionToken('gotrue-token', { origin: ALIAS_ORIGIN, project_id: SHOP }),
      ).rejects.toBeInstanceOf(ForbiddenException);
      expect(state.findings.map((f) => f.rule)).toContain('sso.app_access');
    });

    it('refuses an origin that is not one of the project hosts', async () => {
      const { service, authService } = build('strict');
      signInAs(authService, 'user_member');

      await expect(
        service.issueSessionToken('gotrue-token', { origin: 'https://portal.b.example', project_id: SHOP }),
      ).rejects.toBeInstanceOf(ForbiddenException);
    });

    it('gives the dashboard the full platform token', async () => {
      const { service, authService } = build('strict');
      signInAs(authService, 'user_member');

      const issued = await service.issueSessionToken('gotrue-token', { origin: DASHBOARD, project_id: null });

      const claims = decode(issued.access_token);
      expect(claims).toMatchObject({ sub: 'user_member', type: 'user' });
      expect(claims).not.toHaveProperty('aud');
      expect(claims.orgs).toEqual([{ id: 'org_acme', role: 'member' }]);
      expect(issued.audience).toBeUndefined();
    });
  });

  describe('under audit', () => {
    it('gives an app the full token, as today, and records that strict would give an audience token', async () => {
      const { service, authService } = build('audit');
      signInAs(authService, 'user_member');

      const issued = await service.issueSessionToken('gotrue-token', { origin: ALIAS_ORIGIN, project_id: SHOP });

      expect(decode(issued.access_token)).not.toHaveProperty('aud');
      expect(state.findings.map((f) => f.rule)).toEqual(['sso.audience_token']);
    });

    it('gives a visitor the app does not admit a token, and records that strict would refuse', async () => {
      const { service, authService } = build('audit');
      signInAs(authService, 'user_outsider');

      const issued = await service.issueSessionToken('gotrue-token', { origin: ALIAS_ORIGIN, project_id: SHOP });

      expect(decode(issued.access_token)).not.toHaveProperty('aud');
      expect(state.findings.map((f) => f.rule)).toContain('sso.app_access');
    });

    it('gives a token to an origin strict would refuse, and records it', async () => {
      const { service, authService } = build('audit');
      signInAs(authService, 'user_member');

      await service.issueSessionToken('gotrue-token', { origin: null, project_id: null });

      expect(state.findings).toEqual([
        expect.objectContaining({ rule: 'sso.session_origin', actor_type: 'user', actor_id: 'user_member' }),
      ]);
    });
  });

  describe('under legacy', () => {
    it('gives the full token and records nothing', async () => {
      const { service, authService } = build('legacy');
      signInAs(authService, 'user_outsider');

      const issued = await service.issueSessionToken('gotrue-token', { origin: ALIAS_ORIGIN, project_id: SHOP });

      expect(decode(issued.access_token)).not.toHaveProperty('aud');
      expect(state.findings).toEqual([]);
    });
  });
});
