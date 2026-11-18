import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import type { ProjectAuthConfig } from '@eve/shared';
import { ManifestService } from './manifest.service';
import type { SecretsService } from '../secrets/secrets.service';
import type { AuthUser } from '../auth/auth.types';

type Role = 'owner' | 'admin' | 'member';

/**
 * In-memory stand-ins for the tables manifest sync touches. Any query method
 * the test does not define resolves to [] for list-style names and null
 * otherwise, so the rest of sync runs as a no-op.
 */
const db = vi.hoisted(() => {
  const state = {
    orgs: [] as Array<{ id: string; slug: string }>,
    projects: [] as Array<{ id: string; org_id: string; slug: string; auth_config: unknown }>,
    orgMemberships: [] as Array<{ org_id: string; user_id: string; role: 'owner' | 'admin' | 'member' }>,
  };

  function stub<T extends object>(defined: T): T {
    return new Proxy(defined, {
      get(target, key, receiver) {
        if (typeof key !== 'string' || key in target) return Reflect.get(target, key, receiver);
        const fn = vi.fn(async () => (/^(list|findByProject$|find.*s$)/.test(key) ? [] : null));
        Reflect.set(target, key, fn);
        return fn;
      },
    });
  }

  const projects = stub({
    findById: vi.fn(async (id: string) => state.projects.find((p) => p.id === id) ?? null),
    updateAuthConfig: vi.fn(async (id: string, config: unknown) => {
      const project = state.projects.find((p) => p.id === id);
      if (project) project.auth_config = config;
      return project ?? null;
    }),
  });

  const orgs = stub({
    findById: vi.fn(async (id: string) => state.orgs.find((o) => o.id === id) ?? null),
    findBySlug: vi.fn(async (slug: string) => state.orgs.find((o) => o.slug === slug) ?? null),
  });

  const memberships = stub({
    findOrgMembership: vi.fn(async (userId: string, orgId: string) =>
      state.orgMemberships.find((m) => m.user_id === userId && m.org_id === orgId) ?? null),
  });

  const manifests = stub({
    create: vi.fn(async (row: Record<string, unknown>) => ({
      ...row,
      created_at: new Date(),
      updated_at: new Date(),
    })),
  });

  return { state, projects, orgs, memberships, manifests, stub };
});

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    projectQueries: vi.fn(() => db.projects),
    orgQueries: vi.fn(() => db.orgs),
    membershipQueries: vi.fn(() => db.memberships),
    projectManifestQueries: vi.fn(() => db.manifests),
    environmentQueries: vi.fn(() => db.stub({})),
    ingressAliasQueries: vi.fn(() => db.stub({})),
    customDomainQueries: vi.fn(() => db.stub({})),
    appLinkGrantQueries: vi.fn(() => db.stub({})),
    appLinkSubscriptionQueries: vi.fn(() => db.stub({})),
  };
});

const ORG_A = 'org_a';
const ORG_B = 'org_b';
const PROJECT = 'proj_a';

function joinOrg(userId: string, orgId: string, role: Role): void {
  db.state.orgMemberships.push({ org_id: orgId, user_id: userId, role });
}

function manifestYaml(orgAccess: Record<string, unknown>): string {
  return JSON.stringify({
    schema: 'eve/compose/v2',
    'x-eve': { auth: { login_method: 'magic_link', org_access: orgAccess } },
  });
}

const allowOrgB = { mode: 'allowlist', allowed_orgs: [ORG_A, 'org-b'] };
const domainSignupIntoOrgA = {
  mode: 'project_org',
  domain_signup: { enabled: true, domains: [{ domain: 'example.com', target_org: ORG_A }] },
};

function storedAuthConfig(orgAccess: Record<string, unknown>): ProjectAuthConfig {
  return {
    login_method: 'magic_link',
    self_signup: false,
    invite_requires_password: true,
    allowed_redirect_origins: [],
    org_access: {
      mode: 'project_org',
      allowed_orgs: [ORG_A],
      invite: {},
      domain_signup: { enabled: false, domains: [] },
      ...orgAccess,
    },
  } as unknown as ProjectAuthConfig;
}

function buildService(): ManifestService {
  const secrets = {} as SecretsService;
  const fakeDb = { begin: async (fn: (tx: unknown) => Promise<unknown>) => fn({}) };
  return new ManifestService(fakeDb as never, secrets);
}

async function sync(caller: AuthUser | undefined, orgAccess: Record<string, unknown>) {
  const service = buildService();
  return (service.syncManifest as (...args: unknown[]) => Promise<unknown>)(
    PROJECT,
    { yaml: manifestYaml(orgAccess) },
    caller,
  );
}

describe('ManifestService.syncManifest: app sign-in org references', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    db.state.orgs = [
      { id: ORG_A, slug: 'org-a' },
      { id: ORG_B, slug: 'org-b' },
    ];
    db.state.projects = [{ id: PROJECT, org_id: ORG_A, slug: 'app', auth_config: null }];
    db.state.orgMemberships = [];
  });

  it('refuses a member of the project org who names another org in allowed_orgs', async () => {
    joinOrg('user_member', ORG_A, 'owner');
    await expect(sync({ user_id: 'user_member' }, allowOrgB)).rejects.toBeInstanceOf(ForbiddenException);
    expect(db.projects.updateAuthConfig).not.toHaveBeenCalled();
  });

  it('refuses a member of another org who is only a member there', async () => {
    joinOrg('user_member', ORG_A, 'owner');
    joinOrg('user_member', ORG_B, 'member');
    await expect(sync({ user_id: 'user_member' }, allowOrgB)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('refuses a project-org member who adds a domain sign-up rule for their own org', async () => {
    joinOrg('user_member', ORG_A, 'member');
    await expect(sync({ user_id: 'user_member' }, domainSignupIntoOrgA)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('refuses a job token even when its user is an admin of both orgs', async () => {
    joinOrg('user_admin', ORG_A, 'admin');
    joinOrg('user_admin', ORG_B, 'admin');
    await expect(
      sync({ user_id: 'user_admin', is_job_token: true, job_id: 'app-1234', project_id: PROJECT }, allowOrgB),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('refuses a service token', async () => {
    await expect(
      sync({ user_id: 'system', is_service_token: true, project_id: PROJECT }, domainSignupIntoOrgA),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('refuses a user token bound to the project org for another org', async () => {
    joinOrg('user_admin', ORG_A, 'admin');
    joinOrg('user_admin', ORG_B, 'admin');
    await expect(sync({ user_id: 'user_admin', bound_org_id: ORG_A }, allowOrgB)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('accepts an admin of every named org', async () => {
    joinOrg('user_admin', ORG_A, 'admin');
    joinOrg('user_admin', ORG_B, 'owner');
    await expect(sync({ user_id: 'user_admin' }, allowOrgB)).resolves.toBeTruthy();
    expect(db.projects.updateAuthConfig).toHaveBeenCalledWith(
      PROJECT,
      expect.objectContaining({ org_access: expect.objectContaining({ allowed_orgs: [ORG_A, ORG_B] }) }),
    );
  });

  it('accepts a system admin', async () => {
    await expect(sync({ user_id: 'user_sys', is_admin: true }, allowOrgB)).resolves.toBeTruthy();
  });

  it('accepts an admin of the project org adding a domain sign-up rule for it', async () => {
    joinOrg('user_admin', ORG_A, 'admin');
    await expect(sync({ user_id: 'user_admin' }, domainSignupIntoOrgA)).resolves.toBeTruthy();
  });

  it('accepts an unchanged re-sync by a member', async () => {
    joinOrg('user_member', ORG_A, 'member');
    db.state.projects[0].auth_config = storedAuthConfig({ mode: 'allowlist', allowed_orgs: [ORG_A, ORG_B] });
    await expect(sync({ user_id: 'user_member' }, allowOrgB)).resolves.toBeTruthy();
  });

  it('accepts a member syncing a project-org config with no domain sign-up', async () => {
    joinOrg('user_member', ORG_A, 'member');
    await expect(sync({ user_id: 'user_member' }, { mode: 'project_org' })).resolves.toBeTruthy();
  });

  it('accepts a job token re-syncing an unchanged cross-org config', async () => {
    db.state.projects[0].auth_config = storedAuthConfig({ mode: 'allowlist', allowed_orgs: [ORG_A, ORG_B] });
    await expect(
      sync({ user_id: 'user_member', is_job_token: true, job_id: 'app-1234', project_id: PROJECT }, allowOrgB),
    ).resolves.toBeTruthy();
  });
});
