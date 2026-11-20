import { describe, it, expect, beforeAll, afterAll, beforeEach } from 'vitest';
import postgres from 'postgres';
import { managedDbQueries } from './managed-db.js';
import {
  generateEnvironmentId,
  generateManagedDbInstanceId,
  generateManagedDbTenantId,
  generateOrgId,
  generateProjectId,
} from '@eve/shared';

// Managed database lifecycle: deleting an environment keeps its tenant row
// (queued for drop) instead of failing or orphaning the database, and a
// database destroyed and dropped can be provisioned again on the next deploy.

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

describe('managedDbQueries lifecycle', () => {
  let db: ReturnType<typeof postgres>;
  let managedDb: ReturnType<typeof managedDbQueries>;

  const suffix = Math.random().toString(36).slice(2, 8);
  const orgId = generateOrgId();
  const projectId = generateProjectId();
  const instanceId = generateManagedDbInstanceId();
  let envId: string;

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
    await db`INSERT INTO orgs (id, name, slug) VALUES (${orgId}, ${`Lifecycle Org ${suffix}`}, ${`lc${suffix}`})`;
    await db`
      INSERT INTO projects (id, org_id, name, slug, repo_url, branch)
      VALUES (${projectId}, ${orgId}, ${`Lifecycle Project ${suffix}`}, ${`lc${suffix.slice(0, 6)}`}, 'https://example.com/repo.git', 'main')
    `;
    envId = generateEnvironmentId();
    await db`
      INSERT INTO environments (id, project_id, name, type, namespace)
      VALUES (${envId}, ${projectId}, 'test', 'persistent', ${`eve-lc-${suffix}-test`})
    `;
    await managedDb.createInstance({
      id: instanceId,
      provider: 'local',
      provider_instance_id: `local-${suffix}`,
      region: 'local',
      engine: 'postgres',
      engine_version: '16',
      host: 'localhost',
      port: 5432,
      instance_class: 'db.p1',
    });
  });

  function tenantInput(id = generateManagedDbTenantId(), name = 'acme-shop-test-1a2b3c') {
    return {
      id,
      org_id: orgId,
      project_id: projectId,
      env_id: envId,
      service_name: 'db',
      instance_id: instanceId,
      db_name: name,
      db_user: `${name}-u`,
      class: 'db.p1',
      desired_extensions: [] as string[],
      desired_roles: [],
    };
  }

  it('deletes an environment while its tenant waits to be dropped, keeping the tenant row', async () => {
    const tenant = await managedDb.createTenant(tenantInput());
    await managedDb.softDeleteTenant(tenant.id);

    await db`DELETE FROM environments WHERE id = ${envId}`;

    const [after] = await db<Array<{ status: string; env_id: string | null }>>`
      SELECT status, env_id FROM managed_db_tenants WHERE id = ${tenant.id}
    `;
    expect(after).toBeDefined();
    expect(after.status).toBe('deleting');
    expect(after.env_id).toBeNull();
    const queued = await managedDb.listTenantsNeedingReconciliation();
    expect(queued.map((t) => t.id)).toContain(tenant.id);
  });

  it('provisions again after a destroyed database has been dropped', async () => {
    const first = await managedDb.createTenant(tenantInput());
    await managedDb.softDeleteTenant(first.id);
    await managedDb.markTenantDeleted(first.id);

    const second = await managedDb.createTenant(tenantInput(generateManagedDbTenantId(), 'acme-shop-test-9z8y7x'));

    expect(second.status).toBe('provisioning');
    expect(second.deleted_at).toBeNull();
    expect(second.db_name).toBe('acme-shop-test-9z8y7x');
    expect(await managedDb.findTenantByEnv(envId, 'db')).toMatchObject({ id: second.id });
  });

  it('refuses to provision while the previous database is still being dropped', async () => {
    const first = await managedDb.createTenant(tenantInput());
    await managedDb.softDeleteTenant(first.id);

    await expect(managedDb.createTenant(tenantInput())).rejects.toThrow(/still being deleted/);
  });

  it('refuses to bring a tenant deleted mid-operation back to ready, and queues it for drop', async () => {
    const tenant = await managedDb.createTenant(tenantInput());
    const token = 'op-provision';
    expect(await managedDb.acquireOperationLock(tenant.id, token)).not.toBeNull();
    // The environment is deleted while the reconciler is still provisioning.
    await managedDb.softDeleteTenant(tenant.id);

    const moved = await managedDb.transitionStatus(tenant.id, token, 'ready', {
      providerTenantId: 'local:acme-shop-test-1a2b3c',
      setReady: true,
    });

    expect(moved).toBeNull();
    const [after] = await db<Array<{ status: string; deleted_at: Date | null }>>`
      SELECT status, deleted_at FROM managed_db_tenants WHERE id = ${tenant.id}
    `;
    expect(after.status).toBe('deleting');
    expect(after.deleted_at).not.toBeNull();
    expect(await managedDb.releaseOperationLock(tenant.id, token)).toBe(true);
    expect((await managedDb.listTenantsNeedingReconciliation()).map((t) => t.id)).toContain(tenant.id);
  });

  it('still moves a deleted tenant to deleting, deleted or failed', async () => {
    for (const status of ['deleting', 'failed', 'deleted']) {
      const tenant = await managedDb.createTenant(tenantInput(generateManagedDbTenantId(), `acme-shop-test-${status}`));
      await managedDb.softDeleteTenant(tenant.id);
      const token = `op-${status}`;
      expect(await managedDb.acquireOperationLock(tenant.id, token)).not.toBeNull();

      const moved = await managedDb.transitionStatus(tenant.id, token, status);

      expect(moved?.status).toBe(status);
      await db`DELETE FROM managed_db_tenants WHERE id = ${tenant.id}`;
    }
  });

  it('queues for drop a deleted tenant left in any status but deleted or failed', async () => {
    const ready = await managedDb.createTenant(tenantInput());
    const parked = await managedDb.createTenant({ ...tenantInput(generateManagedDbTenantId(), 'acme-shop-test-2b3c4d'), service_name: 'cache' });
    // Rows an earlier release could leave: deleted, yet ready (or failed).
    await db`UPDATE managed_db_tenants SET status = 'ready', deleted_at = NOW() WHERE id = ${ready.id}`;
    await db`UPDATE managed_db_tenants SET status = 'failed', deleted_at = NOW() WHERE id = ${parked.id}`;

    const queued = (await managedDb.listTenantsNeedingReconciliation()).map((t) => t.id);

    expect(queued).toContain(ready.id);
    expect(queued).not.toContain(parked.id);
  });
});
