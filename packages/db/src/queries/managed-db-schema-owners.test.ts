import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import postgres from 'postgres';
import { managedDbQueries } from './managed-db.js';
import {
  generateEnvironmentId,
  generateManagedDbInstanceId,
  generateManagedDbTenantId,
  generateManagedDbTenantRoleId,
  generateOrgId,
  generateProjectId,
} from '@eve/shared';

// Schema-owner roles are stored apart from the `public` data roles, in
// managed_db_tenant_schema_owners, so a release that does not know them (it
// reads managed_db_tenant_roles only) never drops, rotates or regrants them.
// This release lists both kinds together.

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

describe('managedDbQueries schema-owner roles', () => {
  let db: ReturnType<typeof postgres>;
  let managedDb: ReturnType<typeof managedDbQueries>;

  const suffix = Math.random().toString(36).slice(2, 8);
  const orgId = generateOrgId();
  const projectId = generateProjectId();
  const instanceId = generateManagedDbInstanceId();
  let tenantId: string;

  const ownerUser = `acme-shop-test-u-${suffix}`;
  const appUrl = `postgres://${ownerUser}-app:apppw@db.internal:5432/acme-shop-test-${suffix}`;
  const gotrueUrl = `postgres://${ownerUser}-gotrue:gotruepw@db.internal:5432/acme-shop-test-${suffix}`;

  beforeAll(async () => {
    db = postgres(testDbUrl!);
    managedDb = managedDbQueries(db);
  });

  afterAll(async () => {
    await db`DELETE FROM managed_db_tenants WHERE org_id = ${orgId}`;
    await db`DELETE FROM managed_db_instances WHERE id = ${instanceId}`;
    await db`DELETE FROM environments WHERE project_id = ${projectId}`;
    await db`DELETE FROM projects WHERE id = ${projectId}`;
    await db`DELETE FROM orgs WHERE id = ${orgId}`;
    await db.end();
  });

  beforeEach(async () => {
    await db`DELETE FROM managed_db_tenants WHERE org_id = ${orgId}`;
    await db`DELETE FROM environments WHERE project_id = ${projectId}`;
    await db`DELETE FROM projects WHERE id = ${projectId}`;
    await db`DELETE FROM managed_db_instances WHERE id = ${instanceId}`;
    await db`DELETE FROM orgs WHERE id = ${orgId}`;
    await db`INSERT INTO orgs (id, name, slug) VALUES (${orgId}, ${`Acme ${suffix}`}, ${`acme${suffix}`})`;
    await db`
      INSERT INTO projects (id, org_id, name, slug, repo_url, branch)
      VALUES (${projectId}, ${orgId}, ${`Shop ${suffix}`}, ${`s${suffix}`}, 'https://eve.example/shop.git', 'main')
    `;
    const envId = generateEnvironmentId();
    await db`
      INSERT INTO environments (id, project_id, name, type, namespace)
      VALUES (${envId}, ${projectId}, 'test', 'persistent', ${`eve-acme-${suffix}-test`})
    `;
    await managedDb.createInstance({
      id: instanceId,
      provider: 'local',
      provider_instance_id: `local-${suffix}`,
      region: 'local',
      engine: 'postgres',
      engine_version: '16',
      host: 'db.internal',
      port: 5432,
      instance_class: 'db.p1',
      capacity_json: { max_tenants: 50 },
    });
    tenantId = generateManagedDbTenantId();
    await managedDb.createTenant({
      id: tenantId,
      org_id: orgId,
      project_id: projectId,
      env_id: envId,
      service_name: 'db',
      instance_id: instanceId,
      db_name: `acme-shop-test-${suffix}`,
      db_user: ownerUser,
      class: 'db.p1',
      desired_roles: [
        { name: 'app', grants: 'readwrite' },
        { name: 'gotrue', grants: { schema: 'auth', owner: true } },
      ],
    });
    await managedDb.upsertTenantRole({
      id: generateManagedDbTenantRoleId(),
      tenant_id: tenantId,
      name: 'app',
      grants: 'readwrite',
      db_user: `${ownerUser}-app`,
      credential_secret_ref: appUrl,
    });
    await managedDb.upsertTenantRole({
      id: generateManagedDbTenantRoleId(),
      tenant_id: tenantId,
      name: 'gotrue',
      grants: 'owner',
      schema_name: 'auth',
      db_user: `${ownerUser}-gotrue`,
      credential_secret_ref: gotrueUrl,
    });
  });

  it('keeps the owner grant in the declared roles', async () => {
    const [tenant] = await db<{ desired_roles: unknown }[]>`SELECT desired_roles FROM managed_db_tenants WHERE id = ${tenantId}`;
    expect(tenant.desired_roles).toEqual([
      { name: 'app', grants: 'readwrite' },
      { name: 'gotrue', grants: { schema: 'auth', owner: true } },
    ]);
  });

  it('lists both kinds of role by name, the owner role with its schema', async () => {
    const roles = await managedDb.listTenantRoles(tenantId);
    expect(roles.map(({ name, grants, schema_name, db_user, credential_secret_ref }) => ({
      name, grants, schema_name, db_user, credential_secret_ref,
    }))).toEqual([
      { name: 'app', grants: 'readwrite', schema_name: null, db_user: `${ownerUser}-app`, credential_secret_ref: appUrl },
      { name: 'gotrue', grants: 'owner', schema_name: 'auth', db_user: `${ownerUser}-gotrue`, credential_secret_ref: gotrueUrl },
    ]);
  });

  it('keeps the owner role out of the table a previous release reads', async () => {
    const rows = await db<{ name: string }[]>`SELECT name FROM managed_db_tenant_roles WHERE tenant_id = ${tenantId}`;
    expect(rows.map((row) => row.name)).toEqual(['app']);
  });

  it('refuses a second owner of one schema, and public', async () => {
    await expect(managedDb.upsertTenantRole({
      id: generateManagedDbTenantRoleId(),
      tenant_id: tenantId,
      name: 'gotrue2',
      grants: 'owner',
      schema_name: 'auth',
      db_user: `${ownerUser}-gotrue2`,
      credential_secret_ref: null,
    })).rejects.toThrow();
    await expect(managedDb.upsertTenantRole({
      id: generateManagedDbTenantRoleId(),
      tenant_id: tenantId,
      name: 'pub',
      grants: 'owner',
      schema_name: 'public',
      db_user: `${ownerUser}-pub`,
      credential_secret_ref: null,
    })).rejects.toThrow();
  });

  it('rotates the owner role credential, and keeps it when an upsert gives none', async () => {
    const rotated = gotrueUrl.replace('gotruepw', 'newpw');
    await managedDb.updateTenantRoleCredentialSecretRef(tenantId, 'gotrue', rotated);
    await managedDb.upsertTenantRole({
      id: generateManagedDbTenantRoleId(),
      tenant_id: tenantId,
      name: 'gotrue',
      grants: 'owner',
      schema_name: 'auth',
      db_user: `${ownerUser}-gotrue`,
      credential_secret_ref: null,
    });
    const roles = await managedDb.listTenantRoles(tenantId);
    expect(roles.find((role) => role.name === 'gotrue')?.credential_secret_ref).toBe(rotated);
  });

  it('deletes one role of either kind by name, and every role of the tenant', async () => {
    expect(await managedDb.deleteTenantRole(tenantId, 'gotrue')).toBe(true);
    expect((await managedDb.listTenantRoles(tenantId)).map((role) => role.name)).toEqual(['app']);

    await managedDb.upsertTenantRole({
      id: generateManagedDbTenantRoleId(),
      tenant_id: tenantId,
      name: 'gotrue',
      grants: 'owner',
      schema_name: 'auth',
      db_user: `${ownerUser}-gotrue`,
      credential_secret_ref: gotrueUrl,
    });
    expect(await managedDb.deleteTenantRoles(tenantId)).toBe(2);
    expect(await managedDb.listTenantRoles(tenantId)).toEqual([]);
  });
});
