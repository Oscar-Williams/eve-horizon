import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ManagedDbReconcilerService } from './managed-db-reconciler.service.js';

// A tenant database accepts only its own logins, each login has a connection
// limit from its class, and so does the database as a whole, so one tenant can
// neither connect to another's database nor use up the connections the
// platform shares (however many roles it declares). The database's limit also
// counts Eve's own connections (the platform login is not a superuser on Cloud
// SQL): reconciler work, `eve db`, migrations and the pre-delete pg_dump, so
// it is the class maximum plus a platform reserve of 5.

type FakeSql = ((strings: TemplateStringsArray, ...values: unknown[]) => Promise<unknown[]>) & {
  unsafe: (text: string) => Promise<unknown[]>;
  end: () => Promise<void>;
  statements: string[];
};

function normalizeSql(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/**
 * Logins and databases with their current limit (-1 is "no limit"), as
 * pg_roles and pg_database would answer.
 */
function createFakeSql(limits: Record<string, number> = {}, databaseLimits: Record<string, number> = {}): FakeSql {
  const statements: string[] = [];
  const sql = ((strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = normalizeSql(strings.reduce((acc, part, index) => acc + part + (index < values.length ? `$${index + 1}` : ''), ''));
    statements.push(text);
    if (text.includes('rolconnlimit')) {
      const login = String(values[0]);
      return Promise.resolve(login in limits ? [{ rolconnlimit: limits[login] }] : []);
    }
    if (text.includes('datconnlimit')) {
      const name = String(values[0]);
      return Promise.resolve(name in databaseLimits ? [{ datconnlimit: databaseLimits[name] }] : []);
    }
    return Promise.resolve([]);
  }) as FakeSql;
  sql.unsafe = (text: string) => {
    statements.push(normalizeSql(text));
    return Promise.resolve([]);
  };
  sql.end = vi.fn().mockResolvedValue(undefined);
  sql.statements = statements;
  return sql;
}

const instance = {
  id: 'mdbi_1',
  provider: 'local',
  provider_instance_id: 'local-system-postgres',
  engine_version: '16',
  host: 'db.internal',
  port: 5432,
  status: 'active',
};

const OWNER = 'acme-shop-test-u-1a2b3c';
const DB = 'acme-shop-test-1a2b3c';

function buildTenant(overrides: Record<string, unknown> = {}) {
  return {
    id: 'mdbt_1',
    status: 'provisioning',
    instance_id: instance.id,
    db_name: DB,
    db_user: OWNER,
    class: 'db.p1',
    desired_class: null,
    provider_tenant_id: null,
    credential_secret_ref: null,
    snapshot_on_delete: false,
    org_id: 'org_1',
    project_id: 'proj_1',
    env_id: 'env_1',
    backup_retention: null,
    desired_extensions: [],
    enabled_extensions: [],
    desired_roles: [],
    deleted_at: null,
    ...overrides,
  };
}

function createService(tenants: Array<ReturnType<typeof buildTenant>>, overrides: Record<string, unknown> = {}) {
  const mockDb = Object.assign(() => Promise.resolve([]), { json: vi.fn(), end: vi.fn() }) as unknown as import('@eve/db').Db;
  const service = new ManagedDbReconcilerService(mockDb);
  const managedDb = {
    forceReleaseStaleOperationLocks: vi.fn().mockResolvedValue([]),
    listTenantsNeedingReconciliation: vi.fn().mockResolvedValue(tenants),
    findOrphanedTenants: vi.fn().mockResolvedValue([]),
    acquireOperationLock: vi.fn().mockImplementation(async (id: string) => tenants.find((t) => t.id === id)),
    releaseOperationLock: vi.fn().mockResolvedValue(true),
    findInstanceById: vi.fn().mockResolvedValue(instance),
    listInstances: vi.fn().mockResolvedValue([instance]),
    listTenantsByInstance: vi.fn().mockResolvedValue(tenants),
    transitionStatus: vi.fn().mockResolvedValue(tenants[0]),
    markTenantExtensionsEnabled: vi.fn().mockResolvedValue(tenants[0]),
    listTenantRoles: vi.fn().mockResolvedValue([]),
    upsertTenantRole: vi.fn().mockImplementation(async (input: Record<string, unknown>) => ({ id: 'mdbr_new', ...input })),
    updateTenantRoleGrants: vi.fn().mockResolvedValue(null),
    deleteTenantRole: vi.fn().mockResolvedValue(true),
    deleteTenantRoles: vi.fn().mockResolvedValue(0),
    ...overrides,
  };
  Object.assign(service, { managedDb });
  return { service, managedDb };
}

describe('ManagedDbReconcilerService tenant isolation', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    process.env = { ...originalEnv, DATABASE_URL: 'postgres://eve:eve@localhost:5432/eve?sslmode=disable' };
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  it('revokes public connect and limits the owner when it provisions a database', async () => {
    const adminSql = createFakeSql({ [OWNER]: -1 });
    const { service } = createService([buildTenant()]);
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.reconcile();

    expect(adminSql.statements).toEqual(expect.arrayContaining([
      `REVOKE CONNECT ON DATABASE "${DB}" FROM PUBLIC`,
      `ALTER ROLE "${OWNER}" CONNECTION LIMIT 25`,
    ]));
    const revoke = adminSql.statements.indexOf(`REVOKE CONNECT ON DATABASE "${DB}" FROM PUBLIC`);
    const create = adminSql.statements.findIndex((s) => s.startsWith(`CREATE DATABASE "${DB}"`));
    expect(create).toBeGreaterThanOrEqual(0);
    expect(revoke).toBeGreaterThan(create);
  });

  it('keeps a limit already set on a login', async () => {
    const adminSql = createFakeSql({ [OWNER]: 40 });
    const { service } = createService([buildTenant()]);
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.reconcile();

    expect(adminSql.statements).toContain(`REVOKE CONNECT ON DATABASE "${DB}" FROM PUBLIC`);
    expect(adminSql.statements.some((s) => s.startsWith(`ALTER ROLE "${OWNER}" CONNECTION LIMIT`))).toBe(false);
  });

  it('creates declared roles with the class connection limit', async () => {
    const adminSql = createFakeSql({ [OWNER]: -1 });
    const tenantSql = createFakeSql();
    const { service } = createService([buildTenant({ class: 'db.p2', desired_roles: [{ name: 'app', grants: 'readwrite' }] })]);
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);
    vi.spyOn(service as any, 'connectToTenantDb').mockReturnValue(tenantSql);

    await service.reconcile();

    expect(adminSql.statements).toEqual(expect.arrayContaining([
      expect.stringMatching(new RegExp(`^CREATE ROLE "${OWNER}-app" WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 100 PASSWORD '[0-9a-f]{32}'$`)),
      `ALTER ROLE "${OWNER}" CONNECTION LIMIT 100`,
    ]));
  });

  it('isolates every ready tenant once when the reconciler starts', async () => {
    process.env.EVE_MANAGED_DB_RECONCILER_ENABLED = 'true';
    process.env.EVE_MANAGED_DB_RECONCILER_CRON = '0 0 1 1 *';
    const ready = buildTenant({ status: 'ready' });
    const other = buildTenant({ id: 'mdbt_2', status: 'ready', db_name: 'acme-lab-test-4d5e6f', db_user: 'acme-lab-test-u-4d5e6f' });
    const gone = buildTenant({ id: 'mdbt_3', status: 'deleted', db_name: 'acme-old-test-7a8b9c', db_user: 'acme-old-test-u-7a8b9c' });
    const adminSql = createFakeSql({ [OWNER]: -1, [`${OWNER}-app`]: -1, 'acme-lab-test-u-4d5e6f': 30 });
    const { service } = createService([ready, other, gone], {
      listTenantsNeedingReconciliation: vi.fn().mockResolvedValue([]),
      listTenantRoles: vi.fn().mockImplementation(async (id: string) => (id === 'mdbt_1'
        ? [{ id: 'mdbr_app', tenant_id: 'mdbt_1', name: 'app', grants: 'readwrite', db_user: `${OWNER}-app`, credential_secret_ref: null }]
        : [])),
    });
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.onModuleInit();
    await (service as any).isolationBackfill;
    await service.onModuleDestroy();

    expect(adminSql.statements).toEqual(expect.arrayContaining([
      `REVOKE CONNECT ON DATABASE "${DB}" FROM PUBLIC`,
      `ALTER ROLE "${OWNER}" CONNECTION LIMIT 25`,
      `ALTER ROLE "${OWNER}-app" CONNECTION LIMIT 25`,
      `REVOKE CONNECT ON DATABASE "acme-lab-test-4d5e6f" FROM PUBLIC`,
    ]));
    expect(adminSql.statements.some((s) => s.includes('acme-lab-test-u-4d5e6f" CONNECTION LIMIT'))).toBe(false);
    expect(adminSql.statements.some((s) => s.includes('acme-old-test'))).toBe(false);
  });

  it('limits the database as a whole to the class maximum plus the platform reserve when it has no limit', async () => {
    const adminSql = createFakeSql({ [OWNER]: -1 }, { [DB]: -1 });
    const { service } = createService([buildTenant({ class: 'db.p2' })]);
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.reconcile();

    expect(adminSql.statements).toContain(`ALTER DATABASE "${DB}" CONNECTION LIMIT 105`);
  });

  it('raises a database limit that leaves the platform no reserve', async () => {
    const adminSql = createFakeSql({ [OWNER]: -1 }, { [DB]: 25 });
    const { service } = createService([buildTenant()]);
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.reconcile();

    expect(adminSql.statements).toContain(`ALTER DATABASE "${DB}" CONNECTION LIMIT 30`);
  });

  it('never lowers a database limit already set at or above the class maximum plus the reserve', async () => {
    for (const limit of [30, 40]) {
      const adminSql = createFakeSql({ [OWNER]: -1 }, { [DB]: limit });
      const { service } = createService([buildTenant()]);
      vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

      await service.reconcile();

      expect(adminSql.statements.some((s) => s.startsWith('ALTER DATABASE'))).toBe(false);
    }
  });

  it('limits the databases of ready tenants in the start-up pass, keeping limits already set', async () => {
    process.env.EVE_MANAGED_DB_RECONCILER_ENABLED = 'true';
    process.env.EVE_MANAGED_DB_RECONCILER_CRON = '0 0 1 1 *';
    const ready = buildTenant({ status: 'ready' });
    const other = buildTenant({ id: 'mdbt_2', status: 'ready', db_name: 'acme-lab-test-4d5e6f', db_user: 'acme-lab-test-u-4d5e6f' });
    const adminSql = createFakeSql(
      { [OWNER]: 25, 'acme-lab-test-u-4d5e6f': 25 },
      { [DB]: -1, 'acme-lab-test-4d5e6f': 30 },
    );
    const { service } = createService([ready, other], {
      listTenantsNeedingReconciliation: vi.fn().mockResolvedValue([]),
    });
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.onModuleInit();
    await (service as any).isolationBackfill;
    await service.onModuleDestroy();

    expect(adminSql.statements).toContain(`ALTER DATABASE "${DB}" CONNECTION LIMIT 30`);
    expect(adminSql.statements.some((s) => s.startsWith('ALTER DATABASE "acme-lab-test-4d5e6f"'))).toBe(false);
  });

  it('isolates a tenant again when a change to it finishes, before it is ready', async () => {
    const roleUser = `${OWNER}-app`;
    const adminSql = createFakeSql({ [OWNER]: -1, [roleUser]: -1 }, { [DB]: -1 });
    const { service, managedDb } = createService(
      [buildTenant({ status: 'modifying', desired_roles: [{ name: 'app', grants: 'readwrite' }] })],
      {
        listTenantRoles: vi.fn().mockResolvedValue([
          { id: 'mdbr_app', tenant_id: 'mdbt_1', name: 'app', grants: 'readwrite', db_user: roleUser, credential_secret_ref: null },
        ]),
        transitionStatus: vi.fn().mockImplementation(async () => {
          adminSql.statements.push('-- ready');
          return buildTenant({ status: 'ready' });
        }),
      },
    );
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);

    await service.reconcile();

    const revoke = `REVOKE CONNECT ON DATABASE "${DB}" FROM PUBLIC`;
    expect(adminSql.statements).toEqual(expect.arrayContaining([
      revoke,
      `ALTER DATABASE "${DB}" CONNECTION LIMIT 30`,
      `ALTER ROLE "${OWNER}" CONNECTION LIMIT 25`,
      `ALTER ROLE "${roleUser}" CONNECTION LIMIT 25`,
    ]));
    expect(adminSql.statements.indexOf(revoke)).toBeGreaterThanOrEqual(0);
    expect(adminSql.statements.indexOf('-- ready')).toBeGreaterThan(adminSql.statements.indexOf(revoke));
    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', expect.anything());
  });
});
