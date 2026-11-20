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

function createService(tenant: ReturnType<typeof deletingTenant>, overrides: Record<string, unknown> = {}) {
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
    findTenantById: vi.fn().mockResolvedValue(tenant),
    ...overrides,
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

  // An environment deleted while its tenant is being provisioned (or
  // changed) must still end with the database dropped.
  describe('a tenant deleted while an operation runs', () => {
    beforeEach(() => {
      vi.stubEnv('DATABASE_URL', 'postgres://eve:eve@localhost:5432/eve?sslmode=disable');
    });

    afterEach(() => {
      vi.unstubAllEnvs();
    });

    it('releases its lock when the tenant can no longer become ready', async () => {
      const adminSql = createFakeSql();
      const tenant = deletingTenant({ status: 'provisioning', deleted_at: null, provider_tenant_id: null, credential_secret_ref: null });
      const { service, managedDb } = createService(tenant, { transitionStatus: vi.fn().mockResolvedValue(null) });
      vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

      await service.reconcile();

      const token = managedDb.acquireOperationLock.mock.calls[0][1];
      expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', token, 'ready', expect.anything());
      expect(managedDb.releaseOperationLock).toHaveBeenCalledWith('mdbt_1', token);
    });

    it('drops a deleted tenant left in another status, even with no provider id yet', async () => {
      const adminSql = createFakeSql();
      const tenant = deletingTenant({ status: 'ready', provider_tenant_id: null });
      const { service, managedDb } = createService(tenant);
      vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

      await service.reconcile();

      expect(adminSql.statements).toContain(`DROP DATABASE IF EXISTS "${DB}"`);
      expect(managedDb.markTenantDeleted).toHaveBeenCalledWith('mdbt_1');
    });

    it('queues the tenant for drop, not failed, when its operation fails after the delete', async () => {
      const adminSql = createFakeSql(/^CREATE DATABASE/);
      const tenant = deletingTenant({ status: 'provisioning', deleted_at: null, provider_tenant_id: null, credential_secret_ref: null });
      const { service, managedDb } = createService(tenant, { findTenantById: vi.fn().mockResolvedValue(null) });
      vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

      await service.reconcile();

      expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'deleting', expect.objectContaining({
        error: expect.objectContaining({ code: 'reconcile_error' }),
      }));
      expect(managedDb.transitionStatus).not.toHaveBeenCalledWith('mdbt_1', expect.any(String), 'failed', expect.anything());
    });
  });

  // The race: the reconciler's check finds the tenant live, then the delete
  // lands (deleted_at set, status deleting) before the operation's failure is
  // written. The row, faked here with the store's own rules (transitionStatus
  // lets a deleted tenant move only to deleting, deleted or failed), must end
  // queued for its drop, never at failed with its database kept.
  describe('a delete that lands after the check and before the failure is written', () => {
    beforeEach(() => {
      vi.stubEnv('DATABASE_URL', 'postgres://eve:eve@localhost:5432/eve?sslmode=disable');
    });

    afterEach(() => {
      vi.unstubAllEnvs();
    });

    function racingStore(tenant: ReturnType<typeof deletingTenant>, deletedAt: Date | null) {
      const row = { status: tenant.status as string, deleted_at: deletedAt, token: null as string | null };
      const overrides = {
        acquireOperationLock: vi.fn(async (_id: string, token: string) => { row.token = token; return tenant; }),
        // What the check reads: the tenant as it was before the delete.
        findTenantById: vi.fn(async () => ({ ...tenant, deleted_at: null })),
        findInstanceById: vi.fn().mockResolvedValue(instance),
        transitionStatus: vi.fn(async (_id: string, token: string, status: string) => {
          if (token !== row.token) return null;
          if (row.deleted_at && !['deleting', 'deleted', 'failed'].includes(status)) return null;
          row.status = status;
          row.token = null;
          return { ...tenant, status, deleted_at: row.deleted_at };
        }),
        failOperation: vi.fn(async (_id: string, token: string) => {
          if (token !== row.token) return null;
          row.status = row.deleted_at ? 'deleting' : 'failed';
          row.token = null;
          return { ...tenant, status: row.status, deleted_at: row.deleted_at };
        }),
      };
      return { row, overrides };
    }

    const provisioning = () => deletingTenant({ status: 'provisioning', deleted_at: null, provider_tenant_id: null, credential_secret_ref: null });

    it('leaves a tenant whose operation failed queued for its drop', async () => {
      const tenant = provisioning();
      const { row, overrides } = racingStore(tenant, new Date());
      const { service } = createService(tenant, overrides);
      vi.spyOn(service as any, 'connectToInstance').mockReturnValue(createFakeSql(/^CREATE DATABASE/));

      await service.reconcile();

      expect(row.status).toBe('deleting');
    });

    it('leaves a tenant whose instance is gone queued for its drop', async () => {
      const tenant = provisioning();
      const { row, overrides } = racingStore(tenant, new Date());
      const { service } = createService(tenant, { ...overrides, findInstanceById: vi.fn().mockResolvedValue(null) });

      await service.reconcile();

      expect(row.status).toBe('deleting');
    });

    it('still parks a failed operation at failed when no delete landed', async () => {
      const tenant = provisioning();
      const { row, overrides } = racingStore(tenant, null);
      const { service } = createService(tenant, overrides);
      vi.spyOn(service as any, 'connectToInstance').mockReturnValue(createFakeSql(/^CREATE DATABASE/));

      await service.reconcile();

      expect(row.status).toBe('failed');
    });
  });

  // A failed drop (its error recorded, updated_at its last try) is retried
  // after a wait that doubles with the time since the delete, from 1 minute
  // to at most an hour, so a failing drop or snapshot is not repeated every
  // 30 seconds for a day.
  describe('retry backoff', () => {
    const MINUTE = 60 * 1000;
    const ago = (ms: number) => new Date(Date.now() - ms);

    function failedDrop(deletedAgo: number, triedAgo: number, overrides: Record<string, unknown> = {}) {
      return deletingTenant({
        deleted_at: ago(deletedAgo),
        updated_at: ago(triedAgo),
        last_error_code: 'reconcile_error',
        ...overrides,
      });
    }

    async function run(tenant: ReturnType<typeof deletingTenant>) {
      const adminSql = createFakeSql();
      const { service, managedDb } = createService(tenant);
      vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);
      const snapshot = vi.spyOn(service as any, 'createPreDeleteSnapshot').mockResolvedValue(undefined);
      await service.reconcile();
      return { adminSql, managedDb, snapshot };
    }

    it('waits before retrying a failed drop', async () => {
      // Deleted 10 minutes ago: the wait is 8 minutes; the last try was 5.
      const { adminSql, managedDb } = await run(failedDrop(10 * MINUTE, 5 * MINUTE));

      expect(managedDb.acquireOperationLock).not.toHaveBeenCalled();
      expect(adminSql.statements).toEqual([]);
    });

    it('retries once the wait has passed', async () => {
      const { adminSql, managedDb } = await run(failedDrop(10 * MINUTE, 9 * MINUTE));

      expect(adminSql.statements).toContain(`DROP DATABASE IF EXISTS "${DB}"`);
      expect(managedDb.markTenantDeleted).toHaveBeenCalledWith('mdbt_1');
    });

    it('waits at most an hour', async () => {
      const early = await run(failedDrop(20 * HOUR, 59 * MINUTE));
      expect(early.managedDb.acquireOperationLock).not.toHaveBeenCalled();

      const due = await run(failedDrop(20 * HOUR, 61 * MINUTE));
      expect(due.managedDb.markTenantDeleted).toHaveBeenCalledWith('mdbt_1');
    });

    it('drops a newly deleted tenant at once', async () => {
      const { managedDb } = await run(deletingTenant({ deleted_at: ago(5000), updated_at: ago(5000), last_error_code: null }));

      expect(managedDb.markTenantDeleted).toHaveBeenCalledWith('mdbt_1');
    });

    it('repeats no snapshot before the wait has passed', async () => {
      const { snapshot, managedDb } = await run(
        failedDrop(3 * MINUTE, 30 * 1000, { snapshot_on_delete: true, last_error_code: 'snapshot_failed' }),
      );

      expect(snapshot).not.toHaveBeenCalled();
      expect(managedDb.acquireOperationLock).not.toHaveBeenCalled();
    });
  });
});
