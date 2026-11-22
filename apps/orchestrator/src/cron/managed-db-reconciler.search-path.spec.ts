import { Logger } from '@nestjs/common';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createDb, type Db } from '@eve/db';
import { generateManagedDbRoleUser } from '@eve/shared';
import { ManagedDbReconcilerService } from './managed-db-reconciler.service.js';

/**
 * The reconciler connects to a tenant's database as Eve's platform login.
 * The tenant owner owns that database: it may set the database's search_path
 * and create functions or operators in `public` named like built-ins. Eve's
 * sessions there must not resolve names through that path, from the first
 * query the client sends onwards.
 *
 * The last block needs a real Postgres whose login may create roles and
 * databases: set TEST_DATABASE_URL. It creates and drops its own tenant
 * database and roles.
 */

type ClientOptions = {
  connection: Record<string, string>;
  fetch_types: boolean;
  database: string;
  host: string[];
};

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

const OWNER = 'acme-shop-test-u-1a2b3c';
const DB = 'acme-shop-test-1a2b3c';

const mockDb = Object.assign(() => Promise.resolve([]), { json: vi.fn(), end: vi.fn() }) as unknown as Db;

function optionsOf(client: Db): ClientOptions {
  return (client as unknown as { options: ClientOptions }).options;
}

function createFakeSql(): FakeSql {
  const statements: string[] = [];
  const record = (text: string) => statements.push(text.replace(/\s+/g, ' ').trim());
  const sql = ((strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = strings.reduce((acc, part, index) => acc + part + (index < values.length ? `$${index + 1}` : ''), '');
    record(text);
    if (text.includes('pg_available_extensions')) return Promise.resolve([{ name: values[0] }]);
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

/** Catalog relations and functions a statement names without `pg_catalog.`. */
function unqualifiedCatalogNames(statements: string[]): string[] {
  return statements.flatMap((statement) =>
    [...statement.matchAll(/(?<![\w."])pg_\w+/g)]
      .map(([name]) => name)
      .filter((name) => name !== 'pg_catalog'));
}

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

function provisionedRole(name: string, grants: string) {
  return {
    id: `mdbr_${name}`,
    tenant_id: 'mdbt_1',
    name,
    grants,
    db_user: `${OWNER}-${name}`,
    credential_secret_ref: `postgres://${OWNER}-${name}:old@db.internal:5432/${DB}?sslmode=disable`,
  };
}

function createService(tenant: ReturnType<typeof buildTenant>, managedDbOverrides: Record<string, unknown> = {}) {
  const service = new ManagedDbReconcilerService(mockDb);
  const managedDb = {
    forceReleaseStaleOperationLocks: vi.fn().mockResolvedValue([]),
    listTenantsNeedingReconciliation: vi.fn().mockResolvedValue([tenant]),
    findOrphanedTenants: vi.fn().mockResolvedValue([]),
    acquireOperationLock: vi.fn().mockResolvedValue(tenant),
    releaseOperationLock: vi.fn().mockResolvedValue(true),
    findInstanceById: vi.fn().mockResolvedValue(instance),
    transitionStatus: vi.fn().mockResolvedValue(tenant),
    markTenantExtensionsEnabled: vi.fn().mockResolvedValue(tenant),
    markTenantDeleted: vi.fn().mockResolvedValue(true),
    listTenantRoles: vi.fn().mockResolvedValue([]),
    upsertTenantRole: vi.fn().mockImplementation(async (input: Record<string, unknown>) => ({ id: 'mdbr_new', ...input })),
    updateTenantRoleGrants: vi.fn().mockResolvedValue(null),
    updateTenantRoleCredentialSecretRef: vi.fn().mockResolvedValue(null),
    deleteTenantRole: vi.fn().mockResolvedValue(true),
    deleteTenantRoles: vi.fn().mockResolvedValue(0),
    ...managedDbOverrides,
  };
  Object.assign(service, { managedDb });
  return { service, managedDb };
}

describe('platform connections to tenant databases', () => {
  const originalEnv = { ...process.env };
  const opened: Db[] = [];

  afterEach(async () => {
    process.env = { ...originalEnv };
    await Promise.all(opened.splice(0).map((client) => client.end({ timeout: 0 })));
  });

  function connect(databaseUrl: string) {
    process.env.DATABASE_URL = databaseUrl;
    const service = new ManagedDbReconcilerService(mockDb) as unknown as {
      connectToTenantDb: (target: typeof instance, tenant: { db_name: string }) => Db;
      connectToInstance: (target: typeof instance) => Db;
    };
    const tenantSql = service.connectToTenantDb(instance, { db_name: DB });
    const instanceSql = service.connectToInstance(instance);
    opened.push(tenantSql, instanceSql);
    return { tenant: optionsOf(tenantSql), admin: optionsOf(instanceSql) };
  }

  it('pin search_path to pg_catalog in the startup message and skip the startup type query', () => {
    const { tenant, admin } = connect('postgres://eve:eve@localhost:5432/eve?sslmode=disable');

    expect(tenant.database).toBe(DB);
    expect(tenant.host).toEqual([instance.host]);
    expect(admin.database).toBe('postgres');
    for (const options of [tenant, admin]) {
      expect(options.connection.search_path).toBe('pg_catalog');
      expect(options.fetch_types).toBe(false);
    }
  });

  it('keep the pin when DATABASE_URL sets a search path of its own', () => {
    for (const query of ['search_path=public', 'SEARCH_PATH=public', 'Search_Path=public%2Cpg_catalog']) {
      const { tenant, admin } = connect(`postgres://eve:eve@localhost:5432/eve?sslmode=disable&${query}`);
      for (const options of [tenant, admin]) {
        const searchPaths = Object.entries(options.connection)
          .filter(([name]) => name.toLowerCase() === 'search_path');
        expect(searchPaths).toEqual([['search_path', 'pg_catalog']]);
      }
    }
  });
});

describe('statements on platform connections', () => {
  const originalEnv = { ...process.env };
  let adminSql: FakeSql;
  let tenantSql: FakeSql;

  beforeEach(() => {
    process.env = { ...originalEnv, DATABASE_URL: 'postgres://eve:eve@localhost:5432/eve?sslmode=disable' };
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
    adminSql = createFakeSql();
    tenantSql = createFakeSql();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  function wireConnections(service: ManagedDbReconcilerService) {
    vi.spyOn(service as any, 'connectToInstance').mockReturnValue(adminSql);
    vi.spyOn(service as any, 'connectToTenantDb').mockReturnValue(tenantSql);
  }

  it('name catalog objects by schema and install extensions into "public" when provisioning', async () => {
    const tenant = buildTenant({
      desired_extensions: ['pg_trgm'],
      desired_roles: [{ name: 'app', grants: 'readwrite' }],
    });
    const { service, managedDb } = createService(tenant);
    wireConnections(service);

    await service.reconcile();

    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', expect.anything());
    expect(tenantSql.statements).toEqual(expect.arrayContaining([
      'SELECT name FROM pg_catalog.pg_available_extensions WHERE name = $1',
      'CREATE EXTENSION IF NOT EXISTS "pg_trgm" SCHEMA "public"',
      'SELECT n.nspname AS schema_name FROM pg_catalog.pg_extension e ' +
        'JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace WHERE e.extname = $1',
    ]));
    expect(adminSql.statements).toEqual(expect.arrayContaining([
      'SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = $1',
      'SELECT 1 FROM pg_catalog.pg_database WHERE datname = $1',
    ]));
    expect(unqualifiedCatalogNames([...adminSql.statements, ...tenantSql.statements])).toEqual([]);
  });

  it('name catalog objects by schema when dropping roles and deleting the tenant', async () => {
    const modifying = buildTenant({ status: 'modifying', desired_roles: [] });
    const first = createService(modifying, {
      listTenantRoles: vi.fn().mockResolvedValue([provisionedRole('old_role', 'readonly')]),
    });
    wireConnections(first.service);
    await first.service.reconcile();

    const deleting = buildTenant({ status: 'deleting', provider_tenant_id: `local:${DB}`, deleted_at: new Date() });
    const second = createService(deleting, {
      listTenantRoles: vi.fn().mockResolvedValue([provisionedRole('app', 'readwrite')]),
    });
    wireConnections(second.service);
    await second.service.reconcile();

    expect(first.managedDb.deleteTenantRole).toHaveBeenCalledWith('mdbt_1', 'old_role');
    expect(second.managedDb.markTenantDeleted).toHaveBeenCalledWith('mdbt_1');
    expect(adminSql.statements).toEqual(expect.arrayContaining([
      'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity ' +
        'WHERE usename = $1 AND pid != pg_catalog.pg_backend_pid()',
      'SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity ' +
        'WHERE datname = $1 AND pid != pg_catalog.pg_backend_pid()',
    ]));
    expect(unqualifiedCatalogNames([...adminSql.statements, ...tenantSql.statements])).toEqual([]);
  });
});

const testDbUrl = process.env.TEST_DATABASE_URL;

describe.skipIf(!testDbUrl)('a tenant database that shadows built-ins (real Postgres)', () => {
  const suffix = Math.random().toString(36).slice(2, 8);
  const tenant = { id: 'mdbt_shadow', db_name: `eve_shadow_${suffix}`, db_user: `eve_shadow_${suffix}_owner` };
  const appRole = generateManagedDbRoleUser(tenant.db_user, 'app');
  const originalDatabaseUrl = process.env.DATABASE_URL;
  let target: typeof instance;
  let server: Db;
  let tenantSide: Db;

  /**
   * The tenant owner, inside its own database: put `public` ahead of
   * pg_catalog for every new session and define `=` on oid and on name in
   * `public`. Each operator records the first call in a session (and who
   * made it), then answers as the built-in would.
   */
  const shadowing = [
    `ALTER DATABASE "${tenant.db_name}" SET search_path = public, pg_catalog`,
    'CREATE TABLE public.shadow_calls (called_by text NOT NULL)',
    'GRANT INSERT ON public.shadow_calls TO PUBLIC',
    `CREATE FUNCTION public.shadow_record() RETURNS void LANGUAGE plpgsql AS $$
     BEGIN
       IF pg_catalog.current_setting('shadow.recorded', true) IS NULL THEN
         INSERT INTO public.shadow_calls (called_by) VALUES (current_user);
         PERFORM pg_catalog.set_config('shadow.recorded', 'yes', false);
       END IF;
     END $$`,
    `CREATE FUNCTION public.shadow_oideq(oid, oid) RETURNS boolean LANGUAGE plpgsql AS $$
     BEGIN PERFORM public.shadow_record(); RETURN $1 OPERATOR(pg_catalog.=) $2; END $$`,
    'CREATE OPERATOR public.= (LEFTARG = oid, RIGHTARG = oid, FUNCTION = public.shadow_oideq)',
    `CREATE FUNCTION public.shadow_nameeq(name, name) RETURNS boolean LANGUAGE plpgsql AS $$
     BEGIN PERFORM public.shadow_record(); RETURN $1 OPERATOR(pg_catalog.=) $2; END $$`,
    'CREATE OPERATOR public.= (LEFTARG = name, RIGHTARG = name, FUNCTION = public.shadow_nameeq)',
  ];

  function reconciler() {
    const service = new ManagedDbReconcilerService(mockDb);
    Object.assign(service, {
      managedDb: {
        upsertTenantRole: vi.fn().mockImplementation(async (input: Record<string, unknown>) => input),
      },
    });
    return service as unknown as {
      connectToTenantDb: (target: typeof instance, tenant: { db_name: string }) => Db;
      installTenantExtensions: (target: typeof instance, tenant: object, extensions: string[]) => Promise<void>;
      applyLocalTenantRoleChanges: (target: typeof instance, tenant: object, plan: object) => Promise<void>;
    };
  }

  async function shadowCalls(): Promise<string[]> {
    const rows = await tenantSide<{ called_by: string }[]>`SELECT called_by FROM public.shadow_calls`;
    return rows.map((row) => row.called_by);
  }

  beforeAll(async () => {
    const url = new URL(testDbUrl!);
    target = { ...instance, provider_instance_id: 'local-test', host: url.hostname, port: Number(url.port || 5432) };
    process.env.DATABASE_URL = testDbUrl;
    server = createDb(testDbUrl!);
    await server.unsafe(`CREATE ROLE "${tenant.db_user}" LOGIN`);
    await server.unsafe(`CREATE DATABASE "${tenant.db_name}" OWNER "${tenant.db_user}"`);

    // The test's own view of the tenant database, pinned so it never calls
    // the tenant's operators itself.
    url.pathname = `/${tenant.db_name}`;
    url.searchParams.set('search_path', 'pg_catalog');
    tenantSide = createDb(url.toString());
    await tenantSide.begin(async (tx) => {
      await tx.unsafe(`SET LOCAL ROLE "${tenant.db_user}"`);
      for (const statement of shadowing) await tx.unsafe(statement);
    });
  });

  afterAll(async () => {
    if (originalDatabaseUrl === undefined) delete process.env.DATABASE_URL;
    else process.env.DATABASE_URL = originalDatabaseUrl;
    await tenantSide?.end({ timeout: 1 });
    if (!server) return;
    await server`
      SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = ${tenant.db_name}
    `;
    await server.unsafe(`DROP DATABASE IF EXISTS "${tenant.db_name}"`);
    await server.unsafe(`DROP ROLE IF EXISTS "${appRole}"`);
    await server.unsafe(`DROP ROLE IF EXISTS "${tenant.db_user}"`);
    await server.end({ timeout: 1 });
  });

  it('installs extensions and grants declared roles without calling the tenant\'s operators', async () => {
    const service = reconciler();

    await service.installTenantExtensions(target, tenant, ['pg_trgm']);
    await service.applyLocalTenantRoleChanges(target, tenant, {
      desired: [{ name: 'app', grants: 'readonly' }],
      diff: { create: [{ name: 'app', grants: 'readonly' }], regrant: [], drop: [] },
      provisioned: [],
    });

    expect(await shadowCalls()).toEqual([]);
    const [extension] = await tenantSide<{ schema: string }[]>`
      SELECT n.nspname AS schema
      FROM pg_catalog.pg_extension e
      JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
      WHERE e.extname = 'pg_trgm'
    `;
    expect(extension).toEqual({ schema: 'public' });
    const [usage] = await tenantSide<{ granted: boolean }[]>`
      SELECT pg_catalog.has_schema_privilege(${appRole}, 'public', 'USAGE') AS granted
    `;
    expect(usage).toEqual({ granted: true });
  });

  it('opens sessions on pg_catalog alone, which return arrays as text', async () => {
    const client = reconciler().connectToTenantDb(target, tenant);
    try {
      const [row] = await client<{ search_path: string; names: unknown }[]>`
        SELECT pg_catalog.current_setting('search_path') AS search_path, ARRAY['a', 'b']::text[] AS names
      `;
      expect(row).toEqual({ search_path: 'pg_catalog', names: '{a,b}' });
    } finally {
      await client.end({ timeout: 1 });
    }
    expect(await shadowCalls()).toEqual([]);
  });
});
