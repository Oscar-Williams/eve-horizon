import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ManagedDbReconcilerService } from './managed-db-reconciler.service.js';

// Dropping a tenant database: a failed drop is retried for a day instead of
// parking at `failed` at once; a requested pre-delete snapshot that fails
// stops the drop (the database is kept); and a tenant whose environment row
// is gone (env_id NULL) is still dropped.

type FakeSql = ((strings: TemplateStringsArray, ...values: unknown[]) => Promise<unknown[]>) & {
  unsafe: (text: string) => Promise<unknown[]>;
  end: () => Promise<void>;
  statements: string[];
};

function createFakeSql(failOn?: RegExp): FakeSql {
  const statements: string[] = [];
  const sql = ((strings: TemplateStringsArray, ...values: unknown[]) => {
    statements.push(strings.join('?').replace(/\s+/g, ' ').trim());
    void values;
    return Promise.resolve([]);
  }) as unknown as FakeSql;
  sql.unsafe = (text: string) => {
    statements.push(text);
    if (failOn?.test(text)) return Promise.reject(new Error('database is being accessed by other users'));
    return Promise.resolve([]);
  };
  sql.end = vi.fn().mockResolvedValue(undefined);
  sql.statements = statements;
  return sql;
}

const instance = { id: 'mdbi_1', provider: 'local', provider_instance_id: 'local', host: 'db.internal', port: 5432 };
const DB = 'acme-shop-test-1a2b3c';
const HOUR = 60 * 60 * 1000;

function deletingTenant(overrides: Record<string, unknown> = {}) {
  return {
    id: 'mdbt_1',
    status: 'deleting',
    instance_id: instance.id,
    db_name: DB,
    db_user: `${DB}-u`,
    class: 'db.p1',
    desired_class: null,
    provider_tenant_id: `local:${DB}`,
    credential_secret_ref: `postgres://${DB}-u:pw@db.internal:5432/${DB}`,
    snapshot_on_delete: false,
    org_id: 'org_1',
    project_id: 'proj_1',
    env_id: 'env_1',
    backup_retention: null,
    desired_extensions: [],
    enabled_extensions: [],
    desired_roles: [],
    deleted_at: new Date(Date.now() - HOUR),
    ...overrides,
  };
}

function createService(tenant: ReturnType<typeof deletingTenant>) {
  const mockDb = Object.assign(() => Promise.resolve([]), { json: vi.fn(), end: vi.fn() }) as unknown as import('@eve/db').Db;
  const service = new ManagedDbReconcilerService(mockDb);
  const managedDb = {
    forceReleaseStaleOperationLocks: vi.fn().mockResolvedValue([]),
    listTenantsNeedingReconciliation: vi.fn().mockResolvedValue([tenant]),
    findOrphanedTenants: vi.fn().mockResolvedValue([]),
    acquireOperationLock: vi.fn().mockResolvedValue(tenant),
    releaseOperationLock: vi.fn().mockResolvedValue(true),
    findInstanceById: vi.fn().mockResolvedValue(instance),
    transitionStatus: vi.fn().mockResolvedValue(tenant),
    markTenantDeleted: vi.fn().mockResolvedValue(true),
    listTenantRoles: vi.fn().mockResolvedValue([]),
    deleteTenantRoles: vi.fn().mockResolvedValue(0),
  };
  const environments = { findById: vi.fn().mockResolvedValue(null) };
  const orgs = { findById: vi.fn().mockResolvedValue({ slug: 'acme' }) };
  const projects = { findById: vi.fn().mockResolvedValue({ slug: 'shop' }) };
  Object.assign(service, { managedDb, environments, orgs, projects });
  return { service, managedDb, environments };
}

describe('ManagedDbReconcilerService tenant drop', () => {
  beforeEach(() => {
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('keeps a tenant whose drop failed queued for another try within a day', async () => {
    const adminSql = createFakeSql(/^DROP DATABASE/);
    const { service, managedDb } = createService(deletingTenant());
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.reconcile();

    expect(managedDb.markTenantDeleted).not.toHaveBeenCalled();
    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'deleting', expect.objectContaining({
      error: expect.objectContaining({ message: expect.stringContaining('being accessed') }),
    }));
    expect(managedDb.transitionStatus).not.toHaveBeenCalledWith('mdbt_1', expect.any(String), 'failed', expect.anything());
  });

  it('marks the tenant failed once its drop has failed for a day', async () => {
    const adminSql = createFakeSql(/^DROP DATABASE/);
    const { service, managedDb } = createService(deletingTenant({ deleted_at: new Date(Date.now() - 25 * HOUR) }));
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.reconcile();

    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'failed', expect.anything());
  });

  it('keeps the database when a requested pre-delete snapshot fails', async () => {
    const adminSql = createFakeSql();
    const { service, managedDb } = createService(deletingTenant({ snapshot_on_delete: true }));
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);
    vi.spyOn(service as any, 'createPreDeleteSnapshot').mockRejectedValue(new Error('bucket unavailable'));

    await service.reconcile();

    expect(adminSql.statements.some((s) => s.startsWith('DROP DATABASE'))).toBe(false);
    expect(managedDb.markTenantDeleted).not.toHaveBeenCalled();
    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'deleting', expect.objectContaining({
      error: expect.objectContaining({ message: expect.stringContaining('snapshot') }),
    }));
  });

  it('drops the database of a tenant whose environment is gone', async () => {
    const adminSql = createFakeSql();
    const { service, managedDb, environments } = createService(deletingTenant({ env_id: null }));
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.reconcile();

    expect(adminSql.statements).toContain(`DROP DATABASE IF EXISTS "${DB}"`);
    expect(managedDb.markTenantDeleted).toHaveBeenCalledWith('mdbt_1');
    expect(environments.findById).not.toHaveBeenCalledWith(null);
  });
});
