import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import {
  ALL_PERMISSIONS,
  DEFAULT_ACTION_RUN_JOB_PERMISSIONS,
  DEFAULT_AGENT_PERMISSIONS,
  DEFAULT_SCRIPT_JOB_PERMISSIONS,
  DEFAULT_SERVICE_PERMISSIONS,
} from '@eve/shared';
import { RbacService } from './rbac.service.js';
import { AccessService } from './access.service.js';
import { expandPermissions } from './permissions.js';
import { SecurityService } from '../security/security.service.js';
import type { AuthUser } from './auth.types.js';
import { accessStore as store } from './__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('./__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

const ORG = 'org_acme';
const PROJECT = 'proj_shop';
const member: AuthUser = { user_id: 'user_alice' };
const admin: AuthUser = { user_id: 'user_bob' };
const operator: AuthUser = { user_id: 'user_carol' };

/** A job token that carries the default agent permissions (secrets:read, envdb:read). */
const jobToken: AuthUser = {
  user_id: 'user_alice',
  is_job_token: true,
  job_id: 'shop-1',
  project_id: PROJECT,
  org_id: ORG,
  permissions: [...DEFAULT_AGENT_PERMISSIONS],
} as AuthUser;

function services() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  return { security, rbac, access };
}

/** Rule set 2 is P2's: a project set strict now covers it. */
function seed(profile: 'legacy' | 'audit' | 'strict', ruleset: number | null = profile === 'strict' ? 2 : null) {
  store.reset();
  store.addOrg(ORG, 'acme');
  store.addProject(PROJECT, ORG, 'shop', profile, ruleset);
  store.joinOrg(member.user_id, ORG, 'member');
  store.joinProject(member.user_id, PROJECT, 'member');
  store.joinOrg(admin.user_id, ORG, 'admin');
  store.joinOrg(operator.user_id, ORG, 'member');
  store.joinProject(operator.user_id, PROJECT, 'member');
}

describe('operator rights: secrets:use and envdb:export (P2-7)', () => {
  it('are in the catalog, held by admin and owner, and in no member or default token set', () => {
    expect(ALL_PERMISSIONS).toEqual(expect.arrayContaining(['secrets:use', 'envdb:export']));
    for (const right of ['secrets:use', 'envdb:export'] as const) {
      expect(expandPermissions('admin').has(right)).toBe(true);
      expect(expandPermissions('owner').has(right)).toBe(true);
      expect(expandPermissions('member').has(right)).toBe(false);
      for (const defaults of [DEFAULT_AGENT_PERMISSIONS, DEFAULT_SCRIPT_JOB_PERMISSIONS, DEFAULT_ACTION_RUN_JOB_PERMISSIONS, DEFAULT_SERVICE_PERMISSIONS]) {
        expect(defaults).not.toContain(right);
      }
    }
  });

  describe('under legacy', () => {
    beforeEach(() => seed('legacy'));

    it('lets secrets:read stand for secrets:use and envdb:read for envdb:export, recording nothing', async () => {
      const { rbac } = services();
      await expect(rbac.requireOperatorRight(member, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      await expect(rbac.requireOperatorRight(member, PROJECT, 'envdb:export', 'envdb.export')).resolves.toBeUndefined();
      expect(store.findings()).toEqual([]);
    });

    it('changes nothing for a caller holding neither', async () => {
      store.bind({ org_id: ORG, principal_id: 'user_dave', project_id: PROJECT, permissions: ['jobs:write'] });
      const { rbac } = services();
      await expect(rbac.requireOperatorRight({ user_id: 'user_dave' }, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      expect(store.findings()).toEqual([]);
    });
  });

  describe('under audit', () => {
    beforeEach(() => seed('audit'));

    it('lets a member use secrets and export a database through the read rights, and records each use', async () => {
      // A repeat finding by the same actor is written at most hourly per process, so each use gets its own.
      await expect(services().rbac.requireOperatorRight(member, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      await expect(services().rbac.requireOperatorRight(member, PROJECT, 'envdb:export', 'envdb.export')).resolves.toBeUndefined();

      const recorded = store.findings('access.operator_rights');
      expect(recorded.map((f) => f.detail)).toEqual(expect.arrayContaining([
        expect.objectContaining({ permission: 'secrets:use', implied_by: 'secrets:read' }),
        expect.objectContaining({ permission: 'envdb:export', implied_by: 'envdb:read' }),
      ]));
      expect(recorded[0]).toMatchObject({ profile: 'audit', project_id: PROJECT, actor_type: 'user', actor_id: member.user_id });
    });

    it('records nothing for an admin, who holds the rights', async () => {
      const { rbac } = services();
      await expect(rbac.requireOperatorRight(admin, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      expect(store.findings()).toEqual([]);
    });

    it('lets a job token with only the default permissions through, and records it', async () => {
      const { rbac } = services();
      await expect(rbac.requireOperatorRight(jobToken, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      expect(store.findings('access.operator_rights')[0]).toMatchObject({ actor_type: 'job', actor_id: 'shop-1' });
    });

    it('records a caller with no read right under the use rule, and lets it through', async () => {
      store.bind({ org_id: ORG, principal_id: 'user_dave', project_id: PROJECT, permissions: ['jobs:write'] });
      const { rbac } = services();
      await expect(rbac.requireOperatorRight({ user_id: 'user_dave' }, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      expect(store.findings('secrets.use')[0]).toMatchObject({ profile: 'audit', actor_id: 'user_dave' });
    });

    it('keeps jobs:harness_override in the member set, recording a request that depends on it', async () => {
      const { rbac } = services();
      await expect(rbac.requirePermissions(member, PROJECT, ['jobs:harness_override'])).resolves.toBeUndefined();
      expect(store.findings('access.operator_rights')[0]?.detail).toMatchObject({ permission: 'jobs:harness_override' });

      store.state.findings = [];
      await expect(rbac.requirePermissions(member, PROJECT, ['jobs:write'])).resolves.toBeUndefined();
      expect(store.findings()).toEqual([]);
    });

    it('answers access checks as the run would: allowed, and recorded', async () => {
      const { access } = services();
      await expect(access.can({ org_id: ORG, principal_type: 'user', principal_id: member.user_id, project_id: PROJECT, permission: 'secrets:use' }))
        .resolves.toMatchObject({ allowed: true });
      expect(store.findings('access.operator_rights')).toHaveLength(1);
    });
  });

  describe('under strict', () => {
    beforeEach(() => seed('strict'));

    it('refuses a member who holds only the read rights, and records the refusal', async () => {
      const { rbac } = services();
      await expect(rbac.requireOperatorRight(member, PROJECT, 'secrets:use', 'secrets.use')).rejects.toBeInstanceOf(ForbiddenException);
      await expect(rbac.requireOperatorRight(member, PROJECT, 'envdb:export', 'envdb.export')).rejects.toBeInstanceOf(ForbiddenException);
      expect(store.findings('secrets.use')[0]).toMatchObject({ profile: 'strict', actor_id: member.user_id });
      expect(store.findings('envdb.export')[0]).toMatchObject({ profile: 'strict', actor_id: member.user_id });
    });

    it('lets an admin, and a member given the right by a binding, through', async () => {
      store.bind({ org_id: ORG, principal_id: operator.user_id, project_id: PROJECT, permissions: ['secrets:use', 'envdb:export'] });
      const { rbac } = services();
      await expect(rbac.requireOperatorRight(admin, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      await expect(rbac.requireOperatorRight(operator, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      await expect(rbac.requireOperatorRight(operator, PROJECT, 'envdb:export', 'envdb.export')).resolves.toBeUndefined();
    });

    it('refuses a job token that carries only the default permissions', async () => {
      const { rbac } = services();
      await expect(rbac.requireOperatorRight(jobToken, PROJECT, 'secrets:use', 'secrets.use')).rejects.toBeInstanceOf(ForbiddenException);
      const declared = { ...jobToken, permissions: [...DEFAULT_AGENT_PERMISSIONS, 'secrets:use'] } as AuthUser;
      await expect(rbac.requireOperatorRight(declared, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
    });

    it('takes jobs:harness_override out of the member set; a binding gives it back', async () => {
      store.bind({ org_id: ORG, principal_id: operator.user_id, project_id: PROJECT, permissions: ['jobs:harness_override'] });
      const { rbac } = services();
      await expect(rbac.requirePermissions(member, PROJECT, ['jobs:harness_override'])).rejects.toBeInstanceOf(ForbiddenException);
      await expect(rbac.requirePermissions(member, PROJECT, ['jobs:write'])).resolves.toBeUndefined();
      await expect(rbac.requirePermissions(operator, PROJECT, ['jobs:harness_override'])).resolves.toBeUndefined();
      await expect(rbac.requirePermissions(admin, PROJECT, ['jobs:harness_override'])).resolves.toBeUndefined();
    });

    it('answers access checks the same way', async () => {
      const { access } = services();
      const can = (principal_id: string, permission: string) =>
        access.can({ org_id: ORG, principal_type: 'user', principal_id, project_id: PROJECT, permission });
      await expect(can(member.user_id, 'secrets:use')).resolves.toMatchObject({ allowed: false });
      await expect(can(member.user_id, 'jobs:harness_override')).resolves.toMatchObject({ allowed: false });
      await expect(can(member.user_id, 'secrets:read')).resolves.toMatchObject({ allowed: true });
      await expect(can(admin.user_id, 'secrets:use')).resolves.toMatchObject({ allowed: true });
    });

    it('runs under audit for a project stamped strict before rule set 2', async () => {
      seed('strict', 1);
      const { rbac } = services();
      await expect(rbac.requireOperatorRight(member, PROJECT, 'secrets:use', 'secrets.use')).resolves.toBeUndefined();
      await expect(rbac.requirePermissions(member, PROJECT, ['jobs:harness_override'])).resolves.toBeUndefined();
      expect(store.findings('access.operator_rights')[0]).toMatchObject({ profile: 'audit' });
    });
  });
});
