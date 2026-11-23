import { Logger } from '@nestjs/common';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDb, type Db } from '@eve/db';
import { ManagedDbReconcilerService } from './managed-db-reconciler.service.js';

/**
 * Eve installs a tenant's extensions as its platform login, inside the
 * tenant's own database and into "public", which the tenant can write. An
 * extension script sets its own search path (the target schema, then
 * pg_temp), so an object the tenant plants in "public" can be called by the
 * script with the platform login's rights. PostgreSQL vouches only for the
 * scripts of extensions it marks trusted. The reconciler asks the server
 * which those are and refuses the rest, unless the platform opts in with
 * EVE_MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS=true.
 *
 * The last block needs a real Postgres whose login is a superuser: set
 * TEST_DATABASE_URL. It creates and drops its own tenant database and role.
 */

const OPT_IN = 'EVE_MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS';

// The real-Postgres block lets another untrusted extension stand in for one
// the test server does not have (by manifest name -> Postgres extname).
const standIns = vi.hoisted(() => ({ extnames: {} as Record<string, string> }));

vi.mock('@eve/shared', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/shared')>();
  return {
    ...actual,
    getSupportedExtensionDefinition: (extension: Parameters<typeof actual.getSupportedExtensionDefinition>[0]) => {
      const definition = actual.getSupportedExtensionDefinition(extension);
      const extname = standIns.extnames[extension];
      return extname ? { ...definition, extname } : definition;
    },
  };
});

type CatalogRow = { installed_version: string | null; trusted: boolean | null };

type FakeSql = ((strings: TemplateStringsArray, ...values: unknown[]) => Promise<unknown[]>) & {
  unsafe: (text: string) => Promise<unknown[]>;
  end: () => Promise<void>;
  statements: string[];
};

const instance = {
  id: 'mdbi_1',
  provider: 'local',
  provider_instance_id: 'local-system-postgres',
  engine_version: '16',
  host: 'db.internal',
  port: 5432,
};

const mockDb = Object.assign(() => Promise.resolve([]), { json: vi.fn(), end: vi.fn() }) as unknown as Db;

/** A tenant database whose server reports `catalog` for each Postgres extname. */
function createFakeSql(catalog: Record<string, CatalogRow>): FakeSql {
  const statements: string[] = [];
  const record = (text: string) => statements.push(text.replace(/\s+/g, ' ').trim());
  const sql = ((strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.reduce((acc, part, index) => acc + part + (index < values.length ? `$${index + 1}` : ''), '');
    record(text);
    if (text.includes('pg_available_extensions')) {
      const row = catalog[values[0] as string];
      return Promise.resolve(row ? [{ name: values[0], ...row }] : []);
    }
    if (text.includes('pg_extension')) return Promise.resolve([{ schema_name: 'public' }]);
    return Promise.resolve([]);
  }) as FakeSql;
  sql.unsafe = (text: string) => {
    record(text);
    return Promise.resolve([]);
  };
  sql.end = vi.fn().mockResolvedValue(undefined);
  sql.statements = statements;
  return sql;
}

function buildTenant(overrides: Record<string, unknown> = {}) {
  return {
    id: 'mdbt_1',
    status: 'provisioning',
    instance_id: instance.id,
    db_name: 'acme-shop-test-1a2b3c',
    db_user: 'acme-shop-test-u-1a2b3c',
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

function createService(tenant: ReturnType<typeof buildTenant>) {
  const service = new ManagedDbReconcilerService(mockDb);
  const managedDb = {
    forceReleaseStaleOperationLocks: vi.fn().mockResolvedValue([]),
    listTenantsNeedingReconciliation: vi.fn().mockResolvedValue([tenant]),
    findOrphanedTenants: vi.fn().mockResolvedValue([]),
    acquireOperationLock: vi.fn().mockResolvedValue(tenant),
    findInstanceById: vi.fn().mockResolvedValue(instance),
    transitionStatus: vi.fn().mockResolvedValue(tenant),
    failOperation: vi.fn().mockResolvedValue({ ...tenant, status: 'failed' }),
    markTenantExtensionsEnabled: vi.fn().mockResolvedValue(tenant),
    listTenantRoles: vi.fn().mockResolvedValue([]),
  };
  Object.assign(service, { managedDb });
  return { service, managedDb };
}

const UNTRUSTED: CatalogRow = { installed_version: null, trusted: false };
const TRUSTED: CatalogRow = { installed_version: null, trusted: true };

describe('installing extensions on a tenant database', () => {
  const originalEnv = { ...process.env };
  let adminSql: FakeSql;
  let tenantSql: FakeSql;

  beforeEach(() => {
    process.env = { ...originalEnv, DATABASE_URL: 'postgres://eve:eve@localhost:5432/eve?sslmode=disable' };
    delete process.env[OPT_IN];
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  async function reconcile(tenant: ReturnType<typeof buildTenant>, catalog: Record<string, CatalogRow>) {
    adminSql = createFakeSql({});
    tenantSql = createFakeSql(catalog);
    const { service, managedDb } = createService(tenant);
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);
    vi.spyOn(service as any, 'connectToTenantDb').mockReturnValue(tenantSql);
    await service.reconcile();
    return managedDb;
  }

  const createExtensions = () => tenantSql.statements.filter((statement) => statement.startsWith('CREATE EXTENSION'));

  it('refuses one the server does not mark trusted, naming the opt-in, and runs no install script', async () => {
    const managedDb = await reconcile(buildTenant({ desired_extensions: ['postgis'] }), { postgis: UNTRUSTED });

    expect(managedDb.failOperation).toHaveBeenCalledWith('mdbt_1', expect.any(String), {
        code: 'provider_unsupported',
        message: expect.stringContaining(`${OPT_IN}=true`),
      });
    expect(createExtensions()).toEqual([]);
    expect(managedDb.markTenantExtensionsEnabled).not.toHaveBeenCalled();
  });

  it('goes by the server\'s flag, not the registry\'s expectation', async () => {
    const managedDb = await reconcile(buildTenant({ desired_extensions: ['pg_trgm'] }), { pg_trgm: UNTRUSTED });

    expect(managedDb.failOperation).toHaveBeenCalledWith('mdbt_1', expect.any(String), expect.objectContaining({ code: 'provider_unsupported'),
    });
    expect(createExtensions()).toEqual([]);
  });

  it('refuses one added to a tenant that is already in use', async () => {
    const managedDb = await reconcile(buildTenant({
      status: 'modifying',
      desired_extensions: ['pgvector', 'pg_trgm'],
      enabled_extensions: ['pg_trgm'],
    }), { vector: UNTRUSTED, pg_trgm: { installed_version: '1.6', trusted: true } });

    expect(managedDb.failOperation).toHaveBeenCalledWith('mdbt_1', expect.any(String), expect.objectContaining({ code: 'provider_unsupported'),
    });
    expect(createExtensions()).toEqual([]);
  });

  it('still installs the extensions the server marks trusted', async () => {
    const managedDb = await reconcile(buildTenant({ desired_extensions: ['pg_trgm', 'citext'] }), {
      pg_trgm: TRUSTED,
      citext: TRUSTED,
    });

    expect(createExtensions()).toEqual([
      'CREATE EXTENSION IF NOT EXISTS "pg_trgm" SCHEMA "public"',
      'CREATE EXTENSION IF NOT EXISTS "citext" SCHEMA "public"',
    ]);
    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', expect.anything());
  });

  it('leaves an untrusted extension that is already installed as it is', async () => {
    const managedDb = await reconcile(buildTenant({ desired_extensions: ['postgis'] }), {
      postgis: { installed_version: '3.4.2', trusted: false },
    });

    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', expect.anything());
  });

  it('installs an untrusted extension when the platform opts in with exactly "true"', async () => {
    process.env[OPT_IN] = '1';
    const refused = await reconcile(buildTenant({ desired_extensions: ['postgis'] }), { postgis: UNTRUSTED });
    expect(refused.failOperation).toHaveBeenCalledWith('mdbt_1', expect.any(String), expect.anything());
    expect(createExtensions()).toEqual([]);

    process.env[OPT_IN] = 'true';
    const allowed = await reconcile(buildTenant({ desired_extensions: ['postgis'] }), { postgis: UNTRUSTED });
    expect(createExtensions()).toEqual(['CREATE EXTENSION IF NOT EXISTS "postgis" SCHEMA "public"']);
    expect(allowed.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', expect.anything());
  });
});

const testDbUrl = process.env.TEST_DATABASE_URL;

describe.skipIf(!testDbUrl)('a real tenant database (real Postgres)', () => {
  const suffix = Math.random().toString(36).slice(2, 8);
  const tenant = { id: 'mdbt_ext', db_name: `eve_ext_${suffix}`, db_user: `eve_ext_${suffix}_owner` };
  const originalEnv = { ...process.env };
  let target: typeof instance;
  let server: Db;
  let tenantSide: Db;

  function installTenantExtensions(extensions: string[]): Promise<void> {
    const service = new ManagedDbReconcilerService(mockDb) as unknown as {
      installTenantExtensions: (target: typeof instance, tenant: object, extensions: string[]) => Promise<void>;
    };
    return service.installTenantExtensions(target, tenant, extensions);
  }

  async function installed(): Promise<Array<{ extname: string; schema: string }>> {
    return tenantSide<{ extname: string; schema: string }[]>`
      SELECT e.extname::text AS extname, n.nspname::text AS schema
      FROM pg_catalog.pg_extension e
      JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
      WHERE e.extname <> 'plpgsql'
      ORDER BY 1
    `;
  }

  beforeAll(async () => {
    const url = new URL(testDbUrl!);
    target = { ...instance, provider_instance_id: 'local-test', host: url.hostname, port: Number(url.port || 5432) };
    process.env.DATABASE_URL = testDbUrl;
    // PostGIS is not on the test server; dblink, which PostgreSQL does not
    // mark trusted either, stands in for it.
    standIns.extnames.postgis = 'dblink';
    server = createDb(testDbUrl!);
    await server.unsafe(`CREATE ROLE "${tenant.db_user}" LOGIN`);
    await server.unsafe(`CREATE DATABASE "${tenant.db_name}" OWNER "${tenant.db_user}"`);
    url.pathname = `/${tenant.db_name}`;
    tenantSide = createDb(url.toString());
  });

  afterEach(() => {
    delete process.env[OPT_IN];
  });

  afterAll(async () => {
    process.env = { ...originalEnv };
    delete standIns.extnames.postgis;
    await tenantSide?.end({ timeout: 1 });
    if (!server) return;
    await server`
      SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = ${tenant.db_name}
    `;
    await server.unsafe(`DROP DATABASE IF EXISTS "${tenant.db_name}"`);
    await server.unsafe(`DROP ROLE IF EXISTS "${tenant.db_user}"`);
    await server.end({ timeout: 1 });
  });

  it('installs pg_trgm, which the server marks trusted', async () => {
    await installTenantExtensions(['pg_trgm']);

    expect(await installed()).toEqual([{ extname: 'pg_trgm', schema: 'public' }]);
  });

  it('refuses an extension the server does not mark trusted and installs nothing', async () => {
    await expect(installTenantExtensions(['postgis'])).rejects.toMatchObject({
      code: 'provider_unsupported',
      message: expect.stringContaining(`${OPT_IN}=true`),
    });

    expect(await installed()).toEqual([{ extname: 'pg_trgm', schema: 'public' }]);
  });

  it('installs it into "public" when the platform opts in', async () => {
    process.env[OPT_IN] = 'true';

    await installTenantExtensions(['postgis']);

    expect(await installed()).toEqual([
      { extname: 'dblink', schema: 'public' },
      { extname: 'pg_trgm', schema: 'public' },
    ]);
  });
});
