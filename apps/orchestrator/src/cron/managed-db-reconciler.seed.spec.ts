import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ManagedDbReconcilerService } from './managed-db-reconciler.service.js';

// The local instance seed records the server's real major version and the
// classes the operator configures, and a provider Eve cannot provision for
// fails instead of reporting a database that does not exist.

function platformDb(serverVersionNum: string) {
  return Object.assign(
    (strings: TemplateStringsArray) => Promise.resolve(
      strings.join('?').includes('server_version_num') ? [{ server_version_num: serverVersionNum }] : [],
    ),
    { json: vi.fn(), end: vi.fn() },
  ) as unknown as import('@eve/db').Db;
}

function createService(db: import('@eve/db').Db, overrides: Record<string, unknown> = {}) {
  const service = new ManagedDbReconcilerService(db);
  const managedDb = {
    listInstances: vi.fn().mockResolvedValue([]),
    createInstance: vi.fn().mockImplementation(async (input: Record<string, unknown>) => ({ ...input })),
    listTenantsByInstance: vi.fn().mockResolvedValue([]),
    forceReleaseStaleOperationLocks: vi.fn().mockResolvedValue([]),
    listTenantsNeedingReconciliation: vi.fn().mockResolvedValue([]),
    findOrphanedTenants: vi.fn().mockResolvedValue([]),
    ...overrides,
  };
  Object.assign(service, { managedDb });
  return { service, managedDb };
}

describe('ManagedDbReconcilerService local seed and providers', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      DATABASE_URL: 'postgres://eve:eve@db.internal:5432/eve',
      EVE_MANAGED_DB_RECONCILER_ENABLED: 'true',
      EVE_MANAGED_DB_LOCAL_SEED: 'true',
      EVE_MANAGED_DB_RECONCILER_CRON: '0 0 1 1 *',
    };
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  it('records the server major version', async () => {
    const { service, managedDb } = createService(platformDb('150008'));
    await service.onModuleInit();
    await service.onModuleDestroy();

    expect(managedDb.createInstance).toHaveBeenCalledWith(expect.objectContaining({
      provider: 'local', engine_version: '15', instance_class: 'db.p1',
    }));
  });

  it('seeds one local instance per configured class, once', async () => {
    process.env.EVE_MANAGED_DB_SEED_CLASSES = 'db.p1, db.p2';
    const { service, managedDb } = createService(platformDb('160004'), {
      listInstances: vi.fn().mockResolvedValue([{ id: 'mdbi_old', provider: 'local', instance_class: 'db.p1' }]),
    });
    await service.onModuleInit();
    await service.onModuleDestroy();

    expect(managedDb.createInstance).toHaveBeenCalledTimes(1);
    expect(managedDb.createInstance).toHaveBeenCalledWith(expect.objectContaining({
      provider: 'local', instance_class: 'db.p2', engine_version: '16',
    }));
  });

  it('fails provisioning on a provider it cannot provision for', async () => {
    const tenant = {
      id: 'mdbt_1', status: 'provisioning', instance_id: 'mdbi_cloud', db_name: 'acme-shop-test-1a2b3c',
      db_user: 'acme-shop-test-u-1a2b3c', class: 'db.p1', desired_class: null, provider_tenant_id: null,
      credential_secret_ref: null, snapshot_on_delete: false, org_id: 'org_1', project_id: 'proj_1', env_id: 'env_1',
      backup_retention: null, desired_extensions: [], enabled_extensions: [], desired_roles: [], deleted_at: null,
    };
    const transitionStatus = vi.fn().mockResolvedValue(tenant);
    const { service } = createService(platformDb('150008'), {
      listTenantsNeedingReconciliation: vi.fn().mockResolvedValue([tenant]),
      acquireOperationLock: vi.fn().mockResolvedValue(tenant),
      findInstanceById: vi.fn().mockResolvedValue({ id: 'mdbi_cloud', provider: 'cloudsql', provider_instance_id: 'x', host: 'h', port: 5432 }),
      transitionStatus,
    });

    await service.reconcile();

    expect(transitionStatus).not.toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', expect.anything());
    expect(transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'failed', expect.objectContaining({
      error: expect.objectContaining({ code: 'provider_unsupported' }),
    }));
  });
});
