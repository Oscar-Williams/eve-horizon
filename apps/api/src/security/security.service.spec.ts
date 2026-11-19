import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import { SetSecurityProfileRequestSchema } from '@eve/shared';
import { SecurityService } from './security.service';
import type { AuthUser } from '../auth/auth.types';

/** In-memory stand-ins for system_settings, the profile columns and security_findings. */
const db = vi.hoisted(() => {
  const state = {
    settings: new Map<string, string>(),
    orgProfiles: new Map<string, string | null>(),
    projectProfiles: new Map<string, string | null>(),
    orgRulesets: new Map<string, number | null>(),
    projectRulesets: new Map<string, number | null>(),
    projectOrgs: new Map<string, string>(),
    findings: [] as Array<Record<string, unknown>>,
    /** Stored credentials by format, as `eve system secrets reencrypt --dry-run` counts them. */
    storage: { v1: 0, v2: 0, plainTokens: 0, plainClientSecrets: 0 },
  };

  const settings = {
    get: vi.fn(async (key: string) =>
      state.settings.has(key) ? { key, value: state.settings.get(key) } : null),
    set: vi.fn(async (key: string, value: string) => {
      state.settings.set(key, value);
      return { key, value };
    }),
    delete: vi.fn(async (key: string) => state.settings.delete(key)),
  };

  const security = {
    getProfiles: vi.fn(async (scope: { orgId?: string | null; projectId?: string | null }) => {
      const orgId = scope.orgId ?? (scope.projectId ? state.projectOrgs.get(scope.projectId) : undefined);
      return {
        org_id: orgId ?? null,
        org_profile: orgId ? state.orgProfiles.get(orgId) ?? null : null,
        org_ruleset: orgId ? state.orgRulesets.get(orgId) ?? null : null,
        project_profile: scope.projectId ? state.projectProfiles.get(scope.projectId) ?? null : null,
        project_ruleset: scope.projectId ? state.projectRulesets.get(scope.projectId) ?? null : null,
      };
    }),
    setOrgProfile: vi.fn(async (orgId: string, profile: string | null, ruleset?: number | null) => {
      state.orgProfiles.set(orgId, profile);
      state.orgRulesets.set(orgId, ruleset ?? null);
      return true;
    }),
    setProjectProfile: vi.fn(async (projectId: string, profile: string | null, ruleset?: number | null) => {
      state.projectProfiles.set(projectId, profile);
      state.projectRulesets.set(projectId, ruleset ?? null);
      return true;
    }),
    listOrgProfiles: vi.fn(async () =>
      [...state.orgProfiles.keys()].map((id) => ({
        id,
        slug: id,
        security_profile: state.orgProfiles.get(id) ?? null,
        security_profile_ruleset: state.orgRulesets.get(id) ?? null,
      }))),
    listProjectProfiles: vi.fn(async () =>
      [...state.projectProfiles.keys()].map((id) => ({
        id,
        slug: id,
        org_id: state.projectOrgs.get(id),
        security_profile: state.projectProfiles.get(id) ?? null,
        security_profile_ruleset: state.projectRulesets.get(id) ?? null,
      }))),
    recordFinding: vi.fn(async (finding: Record<string, unknown>) => {
      state.findings.push(finding);
    }),
    listFindings: vi.fn(async () => state.findings),
  };

  const audit = { log: vi.fn(async (entry: Record<string, unknown>) => entry) };

  const secrets = {
    countByFormat: vi.fn(async () => ({ v1: state.storage.v1, v2: state.storage.v2 })),
  };
  const integrations = {
    countTokenFormats: vi.fn(async () => ({ plain: state.storage.plainTokens, sealed: 0 })),
  };
  const oauthAppConfigs = {
    countClientSecretFormats: vi.fn(async () => ({ plain: state.storage.plainClientSecrets, sealed: 0 })),
  };

  return { state, settings, security, audit, secrets, integrations, oauthAppConfigs };
});

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    systemSettingsQueries: vi.fn(() => db.settings),
    securityQueries: vi.fn(() => db.security),
    auditQueries: vi.fn(() => db.audit),
    secretQueries: vi.fn(() => db.secrets),
    integrationQueries: vi.fn(() => db.integrations),
    oauthAppConfigQueries: vi.fn(() => db.oauthAppConfigs),
  };
});

const ORG = 'org_a';
const PROJECT = 'proj_a';
const member: AuthUser = { user_id: 'user_m' };

function build(): SecurityService {
  return new SecurityService({ begin: async (work: (tx: unknown) => Promise<unknown>) => work({}) } as never);
}

describe('SecurityService', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    db.state.settings.clear();
    db.state.orgProfiles.clear();
    db.state.projectProfiles.clear();
    db.state.orgRulesets.clear();
    db.state.projectRulesets.clear();
    db.state.projectOrgs = new Map([[PROJECT, ORG]]);
    db.state.findings = [];
    db.state.storage = { v1: 0, v2: 0, plainTokens: 0, plainClientSecrets: 0 };
  });

  describe('effectiveProfile', () => {
    it('resolves the project, then the org, then the instance', async () => {
      db.state.settings.set('security.profile', 'audit');
      db.state.orgProfiles.set(ORG, 'legacy');
      db.state.projectProfiles.set(PROJECT, 'strict');
      const svc = build();
      expect(await svc.effectiveProfile({ projectId: PROJECT }, 'project')).toBe('strict');
      expect(await svc.effectiveProfile({ projectId: PROJECT }, 'org')).toBe('legacy');
      expect(await svc.effectiveProfile({ projectId: PROJECT }, 'instance')).toBe('audit');
    });

    it('is legacy when nothing is set', async () => {
      expect(await build().effectiveProfile({ projectId: PROJECT }, 'project')).toBe('legacy');
    });
  });

  describe('gate', () => {
    it('allows and records nothing under legacy', async () => {
      db.state.settings.set('security.profile', 'legacy');
      await expect(
        build().gate('test.rule', { projectId: PROJECT, governing: 'project', actor: member }),
      ).resolves.toBe('allowed');
      expect(db.security.recordFinding).not.toHaveBeenCalled();
    });

    it('allows and records a finding under audit, once per key', async () => {
      db.state.settings.set('security.profile', 'audit');
      const svc = build();
      const ctx = { projectId: PROJECT, governing: 'project' as const, actor: member, detail: { route: 'x' } };
      await expect(svc.gate('test.rule', ctx)).resolves.toBe('recorded');
      await expect(svc.gate('test.rule', ctx)).resolves.toBe('recorded');
      expect(db.security.recordFinding).toHaveBeenCalledTimes(1);
      expect(db.state.findings[0]).toMatchObject({
        rule: 'test.rule',
        profile: 'audit',
        org_id: ORG,
        project_id: PROJECT,
        actor_type: 'user',
        actor_id: 'user_m',
        detail: { route: 'x' },
      });
    });

    it('refuses with 403 and records under strict', async () => {
      db.state.projectProfiles.set(PROJECT, 'strict');
      await expect(
        build().gate('test.rule', { projectId: PROJECT, governing: 'project', actor: member }, 'Not allowed'),
      ).rejects.toBeInstanceOf(ForbiddenException);
      expect(db.state.findings[0]).toMatchObject({ rule: 'test.rule', profile: 'strict' });
    });

    it('names job, service and service-principal actors by what they are', async () => {
      db.state.settings.set('security.profile', 'audit');
      const svc = build();
      await svc.gate('a', { projectId: PROJECT, governing: 'project', actor: { user_id: 'u', is_job_token: true, job_id: 'app-1' } });
      await svc.gate('b', { projectId: PROJECT, governing: 'project', actor: { user_id: 'system', is_service_token: true, service_name: 'api', project_id: PROJECT } });
      await svc.gate('c', { projectId: PROJECT, governing: 'project', actor: undefined });
      expect(db.state.findings.map((f) => [f.actor_type, f.actor_id])).toEqual([
        ['job', 'app-1'],
        ['service', 'api'],
        ['none', 'none'],
      ]);
    });
  });

  describe('setProfile', () => {
    it('changes a profile and records the change in one transaction', async () => {
      const tx = { transaction: true };
      const svc = new SecurityService({ begin: async (work: (t: unknown) => Promise<unknown>) => work(tx) } as never);
      const { auditQueries, securityQueries, systemSettingsQueries } = await import('@eve/db');

      await svc.setProfile({ scope: 'org', id: ORG }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'instance' }, 'strict', 'user_admin');

      expect(db.audit.log).toHaveBeenCalledTimes(2);
      expect(vi.mocked(auditQueries).mock.calls.map(([arg]) => arg)).toContain(tx);
      expect(vi.mocked(securityQueries).mock.calls.map(([arg]) => arg)).toContain(tx);
      expect(vi.mocked(systemSettingsQueries).mock.calls.map(([arg]) => arg)).toContain(tx);
    });

    it('records who changed a profile, and from what', async () => {
      db.state.settings.set('security.profile', 'audit');
      db.state.orgProfiles.set(ORG, 'audit');
      const svc = build();

      await svc.setProfile({ scope: 'org', id: ORG }, 'legacy', 'user_admin');
      await svc.setProfile({ scope: 'project', id: PROJECT }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'instance' }, null, 'user_admin');

      expect(db.audit.log.mock.calls.map(([entry]) => entry)).toEqual([
        expect.objectContaining({
          entity_type: 'security_profile', entity_id: `org:${ORG}`, action: 'updated',
          actor: 'user_admin', actor_type: 'user', changes: { profile: { old: 'audit', new: 'legacy' } },
        }),
        expect.objectContaining({ entity_id: `project:${PROJECT}`, changes: { profile: { old: null, new: 'strict' } } }),
        expect.objectContaining({ entity_id: 'instance', changes: { profile: { old: 'audit', new: null } } }),
      ]);
    });

    it('sets the instance, an org, a project and the new-project default', async () => {
      const svc = build();
      await svc.setProfile({ scope: 'instance' }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'org', id: ORG }, 'audit', 'user_admin');
      await svc.setProfile({ scope: 'project', id: PROJECT }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'new_projects' }, 'strict', 'user_admin');
      expect(db.state.settings.get('security.profile')).toBe('strict');
      expect(db.state.settings.get('security.new_project_profile')).toBe('strict');
      expect(db.state.orgProfiles.get(ORG)).toBe('audit');
      expect(db.state.projectProfiles.get(PROJECT)).toBe('strict');
    });

    it('clears an org or project profile with null', async () => {
      db.state.projectProfiles.set(PROJECT, 'strict');
      await build().setProfile({ scope: 'project', id: PROJECT }, null, 'user_admin');
      expect(db.state.projectProfiles.get(PROJECT)).toBeNull();
    });

    it('refuses a value that is not a profile', async () => {
      await expect(
        build().setProfile({ scope: 'instance' }, 'enforce' as never, 'user_admin'),
      ).rejects.toBeInstanceOf(BadRequestException);
    });

    it('refuses an org or project scope with no id', async () => {
      await expect(build().setProfile({ scope: 'org' }, 'strict', 'user_admin')).rejects.toBeInstanceOf(
        BadRequestException,
      );
    });

    it('is seen at once by the process that set it', async () => {
      db.state.settings.set('security.profile', 'audit');
      const svc = build();
      expect(await svc.effectiveProfile({ projectId: PROJECT }, 'project')).toBe('audit');
      await svc.setProfile({ scope: 'project', id: PROJECT }, 'strict', 'user_admin');
      expect(await svc.effectiveProfile({ projectId: PROJECT }, 'project')).toBe('strict');
    });
  });

  describe('applyNewProjectProfile', () => {
    it('writes the instance default for new projects onto a new project', async () => {
      db.state.settings.set('security.new_project_profile', 'strict');
      await build().applyNewProjectProfile(PROJECT);
      expect(db.state.projectProfiles.get(PROJECT)).toBe('strict');
    });

    it('leaves the project to inherit when no default is set', async () => {
      await build().applyNewProjectProfile(PROJECT);
      expect(db.security.setProjectProfile).not.toHaveBeenCalled();
    });
  });
  describe('profile stamps', () => {
    const P1_RULE = 'jobs.run_step_change';
    const P2_RULE = 'isolation.runner_mode';

    it('runs a rule newer than the project stamp under audit, and older rules under strict', async () => {
      db.state.projectProfiles.set(PROJECT, 'strict');
      db.state.projectRulesets.set(PROJECT, 1);
      const svc = build();
      const ctx = { projectId: PROJECT, governing: 'project' as const, actor: member };

      expect(await svc.decide(P2_RULE, ctx)).toBe('audit');
      await expect(svc.gate(P2_RULE, ctx)).resolves.toBe('recorded');
      await expect(svc.gate(P1_RULE, ctx)).rejects.toBeInstanceOf(ForbiddenException);
      expect(await svc.effectiveProfile({ projectId: PROJECT }, 'project', P2_RULE)).toBe('audit');
      expect(await svc.effectiveProfile({ projectId: PROJECT }, 'project', P1_RULE)).toBe('strict');
      expect(db.state.findings.find((f) => f.rule === P2_RULE)).toMatchObject({ profile: 'audit' });
    });

    it('reads a strict profile with no stamp as rule set 1', async () => {
      db.state.orgProfiles.set(ORG, 'strict');
      const svc = build();
      expect(await svc.decide(P2_RULE, { projectId: PROJECT, governing: 'project' })).toBe('audit');
      expect(await svc.decide(P1_RULE, { projectId: PROJECT, governing: 'project' })).toBe('strict');
    });

    it('honours the instance stamp for instance rules', async () => {
      db.state.settings.set('security.profile', 'strict');
      db.state.settings.set('security.profile_ruleset', '1');
      const svc = build();
      expect(await svc.decide('secrets.legacy_ciphertext', { governing: 'instance' })).toBe('audit');
      expect(await svc.decide('sso.app_access', { governing: 'instance' })).toBe('strict');
    });

    it('stamps the current rule set when strict is set again, which takes the new rules', async () => {
      db.state.projectProfiles.set(PROJECT, 'strict');
      db.state.projectRulesets.set(PROJECT, 1);
      const svc = build();
      await svc.setProfile({ scope: 'project', id: PROJECT }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'org', id: ORG }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'instance' }, 'strict', 'user_admin');

      expect(db.state.projectRulesets.get(PROJECT)).toBe(2);
      expect(db.state.orgRulesets.get(ORG)).toBe(2);
      expect(db.state.settings.get('security.profile_ruleset')).toBe('2');
      expect(await svc.decide(P2_RULE, { projectId: PROJECT, governing: 'project' })).toBe('strict');
    });

    it('clears the stamp when a profile other than strict is set', async () => {
      db.state.settings.set('security.profile_ruleset', '1');
      const svc = build();
      await svc.setProfile({ scope: 'project', id: PROJECT }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'project', id: PROJECT }, 'audit', 'user_admin');
      await svc.setProfile({ scope: 'instance' }, 'audit', 'user_admin');
      expect(db.state.projectRulesets.get(PROJECT)).toBeNull();
      expect(db.state.settings.has('security.profile_ruleset')).toBe(false);
    });

    it('stamps a new project created under new_project_profile=strict with the current rule set', async () => {
      db.state.settings.set('security.new_project_profile', 'strict');
      await build().applyNewProjectProfile(PROJECT);
      expect(db.state.projectProfiles.get(PROJECT)).toBe('strict');
      expect(db.state.projectRulesets.get(PROJECT)).toBe(2);
    });

    it('reports the rule set each strict profile covers', async () => {
      db.state.projectProfiles.set(PROJECT, 'strict');
      db.state.projectRulesets.set(PROJECT, 1);
      db.state.orgProfiles.set(ORG, 'audit');
      const report = await build().report({});
      expect(report.current_ruleset).toBe(2);
      expect(report.projects.find((p) => p.id === PROJECT)).toMatchObject({
        profile: 'strict',
        ruleset: 1,
        effective: 'strict',
        effective_ruleset: 1,
      });
      expect(report.orgs.find((o) => o.id === ORG)).toMatchObject({ effective: 'audit', effective_ruleset: null });
    });
  });
  describe('the instance strict guard on legacy credentials', () => {
    it('refuses the instance strict with 409 while v1 secrets or plain OAuth columns remain, naming the command and the count', async () => {
      db.state.settings.set('security.profile', 'audit');
      db.state.storage = { v1: 2, v2: 5, plainTokens: 1, plainClientSecrets: 1 };
      const svc = build();

      const refused = svc.setProfile({ scope: 'instance' }, 'strict', 'user_admin');
      await expect(refused).rejects.toBeInstanceOf(ConflictException);
      await expect(svc.setProfile({ scope: 'instance' }, 'strict', 'user_admin')).rejects.toThrow(/eve system secrets reencrypt/);
      await expect(svc.setProfile({ scope: 'instance' }, 'strict', 'user_admin')).rejects.toThrow(/\b4\b/);
      expect(db.state.settings.get('security.profile')).toBe('audit');
      expect(db.state.settings.has('security.profile_ruleset')).toBe(false);
      expect(db.audit.log).not.toHaveBeenCalled();
    });

    it('sets the instance strict with force, and records that it was forced', async () => {
      db.state.storage = { v1: 1, v2: 0, plainTokens: 0, plainClientSecrets: 0 };
      await build().setProfile({ scope: 'instance' }, 'strict', 'user_admin', { force: true });
      expect(db.state.settings.get('security.profile')).toBe('strict');
      expect(db.audit.log).toHaveBeenCalledWith(expect.objectContaining({
        entity_id: 'instance',
        context: expect.objectContaining({ forced_with_legacy_credentials: 1 }),
      }));
    });

    it('sets the instance strict when no legacy credentials remain', async () => {
      db.state.storage = { v1: 0, v2: 3, plainTokens: 0, plainClientSecrets: 0 };
      await build().setProfile({ scope: 'instance' }, 'strict', 'user_admin');
      expect(db.state.settings.get('security.profile')).toBe('strict');
    });

    it('leaves org, project, new-project and non-strict instance changes alone', async () => {
      db.state.storage = { v1: 3, v2: 0, plainTokens: 2, plainClientSecrets: 0 };
      const svc = build();
      await svc.setProfile({ scope: 'org', id: ORG }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'project', id: PROJECT }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'new_projects' }, 'strict', 'user_admin');
      await svc.setProfile({ scope: 'instance' }, 'audit', 'user_admin');
      expect(db.state.orgProfiles.get(ORG)).toBe('strict');
      expect(db.state.projectProfiles.get(PROJECT)).toBe('strict');
      expect(db.state.settings.get('security.profile')).toBe('audit');
      expect(db.secrets.countByFormat).not.toHaveBeenCalled();
    });

    it('accepts force in the request body', () => {
      expect(SetSecurityProfileRequestSchema.safeParse({ scope: 'instance', profile: 'strict', force: true }).success)
        .toBe(true);
    });
  });
});
