/**
 * Profile stamps against a migrated database: a `strict` profile covers the
 * rule set it was set at, so a rule from a later release runs under `audit`
 * until the profile is set again. Outside the API, `decideSecurityRule` and
 * `governingSecurityProfile` honour the stamps as the API does.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import postgres from 'postgres';
import { decideSecurityRule, governingSecurityProfile, securityQueries } from './security.js';
import type { Db } from '../client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 8);
const org = `org_acme${suffix}`;
const project = `proj_shop${suffix}`;
const P1_RULE = 'jobs.run_step_change';
const P2_RULE = 'isolation.runner_mode';
const P2_INSTANCE_RULE = 'secrets.legacy_ciphertext';

describe('security profile stamps', () => {
  let db: Db;
  let instanceProfile: string | null = null;
  let instanceRuleset: string | null = null;

  async function setting(key: string): Promise<string | null> {
    const [row] = await db<{ value: string }[]>`SELECT value FROM system_settings WHERE key = ${key}`;
    return row?.value ?? null;
  }

  async function putSetting(key: string, value: string | null): Promise<void> {
    if (value === null) {
      await db`DELETE FROM system_settings WHERE key = ${key}`;
      return;
    }
    await db`
      INSERT INTO system_settings (key, value) VALUES (${key}, ${value})
      ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
    `;
  }

  async function findings(rule: string): Promise<Array<{ profile: string }>> {
    return db<{ profile: string }[]>`
      SELECT profile FROM security_findings WHERE rule = ${rule} AND project_id = ${project}
    `;
  }

  function decide(rule: string) {
    return decideSecurityRule(db, rule, {
      projectId: project,
      governing: 'project',
      actorType: 'job',
      actorId: `job_${suffix}`,
    });
  }

  beforeAll(async () => {
    db = postgres(testDbUrl!, { max: 2 }) as unknown as Db;
    instanceProfile = await setting('security.profile');
    instanceRuleset = await setting('security.profile_ruleset');
    await db`INSERT INTO orgs (id, name, slug) VALUES (${org}, ${org}, ${`acme${suffix}`})`;
    await db`
      INSERT INTO projects (id, org_id, name, slug, repo_url)
      VALUES (${project}, ${org}, ${project}, ${`s${suffix}`}, 'https://example.com/repo.git')
    `;
  });

  afterAll(async () => {
    await putSetting('security.profile', instanceProfile);
    await putSetting('security.profile_ruleset', instanceRuleset);
    await db`DELETE FROM security_findings WHERE org_id = ${org} OR project_id = ${project}`;
    await db`DELETE FROM projects WHERE id = ${project}`;
    await db`DELETE FROM orgs WHERE id = ${org}`;
    await (db as unknown as { end: () => Promise<void> }).end();
  });

  it('writes the stamp given with strict, and reads it back', async () => {
    const security = securityQueries(db);
    await security.setProjectProfile(project, 'strict', 1);
    expect(await security.getProfiles({ projectId: project })).toMatchObject({
      org_id: org,
      project_profile: 'strict',
      project_ruleset: 1,
    });
    await security.setOrgProfile(org, 'strict', 2);
    expect(await security.getProfiles({ orgId: org })).toMatchObject({ org_profile: 'strict', org_ruleset: 2 });
  });

  it('runs a rule newer than a project stamp under audit, outside the API', async () => {
    await securityQueries(db).setProjectProfile(project, 'strict', 1);

    expect(await decide(P2_RULE)).toBe('audit');
    expect(await decide(P1_RULE)).toBe('strict');
    expect(await findings(P2_RULE)).toEqual([{ profile: 'audit' }]);
    expect(await governingSecurityProfile(db, { projectId: project, governing: 'project', rule: P2_RULE })).toBe('audit');
    expect(await governingSecurityProfile(db, { projectId: project, governing: 'project', rule: P1_RULE })).toBe('strict');
    expect(await governingSecurityProfile(db, { projectId: project, governing: 'project' })).toBe('strict');
  });

  it('runs every rule under strict once the profile is stamped with its rule set', async () => {
    await securityQueries(db).setProjectProfile(project, 'strict', 2);
    expect(await decide(P2_RULE)).toBe('strict');
    expect(await decide(P1_RULE)).toBe('strict');
  });

  it('clears the stamp when a profile other than strict is written', async () => {
    const security = securityQueries(db);
    await security.setProjectProfile(project, 'strict', 2);
    await security.setProjectProfile(project, 'audit', null);
    expect(await security.getProfiles({ projectId: project })).toMatchObject({
      project_profile: 'audit',
      project_ruleset: null,
    });
  });

  it('drops the stamp when a release that does not know it changes the profile', async () => {
    const security = securityQueries(db);
    await security.setProjectProfile(project, 'strict', 2);
    await security.setOrgProfile(org, 'strict', 2);

    // A release before stamps (0.1.326) sets the profile alone: audit, then strict again.
    await db`UPDATE projects SET security_profile = 'audit', updated_at = NOW() WHERE id = ${project}`;
    await db`UPDATE orgs SET security_profile = 'audit' WHERE id = ${org}`;
    expect(await security.getProfiles({ projectId: project })).toMatchObject({ project_ruleset: null, org_ruleset: null });
    await db`UPDATE projects SET security_profile = 'strict' WHERE id = ${project}`;
    await db`UPDATE orgs SET security_profile = 'strict' WHERE id = ${org}`;

    // Back on this release, the P2 rules start in audit again.
    expect(await security.getProfiles({ projectId: project })).toMatchObject({
      project_profile: 'strict',
      project_ruleset: null,
      org_profile: 'strict',
      org_ruleset: null,
    });
    expect(await decide(P2_RULE)).toBe('audit');
    expect(await decide(P1_RULE)).toBe('strict');
  });

  it('keeps the stamp this release writes with a profile, and through other updates', async () => {
    const security = securityQueries(db);
    await security.setProjectProfile(project, 'audit', null);
    await security.setProjectProfile(project, 'strict', 2);
    expect(await security.getProfiles({ projectId: project })).toMatchObject({ project_profile: 'strict', project_ruleset: 2 });
    await security.setProjectProfile(project, 'strict', 2);
    await db`UPDATE projects SET name = ${`${project}-renamed`} WHERE id = ${project}`;
    expect(await security.getProfiles({ projectId: project })).toMatchObject({ project_profile: 'strict', project_ruleset: 2 });

    await security.setOrgProfile(org, 'legacy', null);
    await security.setOrgProfile(org, 'strict', 2);
    expect(await security.getProfiles({ orgId: org })).toMatchObject({ org_profile: 'strict', org_ruleset: 2 });
    await security.setOrgProfile(org, null, null);
    expect(await security.getProfiles({ orgId: org })).toMatchObject({ org_profile: null, org_ruleset: null });
  });

  it('honours the instance stamp for instance rules', async () => {
    await putSetting('security.profile', 'strict');
    await putSetting('security.profile_ruleset', '1');
    expect(await governingSecurityProfile(db, { governing: 'instance', rule: P2_INSTANCE_RULE })).toBe('audit');
    expect(await governingSecurityProfile(db, { governing: 'instance', rule: 'sso.app_access' })).toBe('strict');
    await putSetting('security.profile_ruleset', '2');
    expect(await governingSecurityProfile(db, { governing: 'instance', rule: P2_INSTANCE_RULE })).toBe('strict');
  });

  it('migration 00116 stamps profiles already strict with rule set 1', async () => {
    await db`UPDATE projects SET security_profile = 'strict', security_profile_ruleset = NULL WHERE id = ${project}`;
    await db`UPDATE orgs SET security_profile = 'audit', security_profile_ruleset = NULL WHERE id = ${org}`;
    await putSetting('security.profile', 'strict');
    await putSetting('security.profile_ruleset', null);

    const here = dirname(fileURLToPath(import.meta.url));
    const migration = readFileSync(join(here, '../../migrations/00116_security_profile_rulesets.sql'), 'utf8');
    await db.begin(async (tx) => {
      await (tx as unknown as Db).unsafe(migration);
    });

    expect(await securityQueries(db).getProfiles({ projectId: project })).toMatchObject({
      project_ruleset: 1,
      org_ruleset: null,
    });
    expect(await setting('security.profile_ruleset')).toBe('1');
  });
});
