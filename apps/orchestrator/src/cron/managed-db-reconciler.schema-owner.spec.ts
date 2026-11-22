import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ManagedDbReconcilerService } from './managed-db-reconciler.service.js';

// Schema-owner roles (EVE-071): a declared role that owns one schema of the
// tenant database. The reconciler creates its login, gives it the schema
// (new, or handed over from the tenant owner) on every run, refuses a schema
// another role holds, and hands the schema back before dropping the login.

type FakeSql = ((strings: TemplateStringsArray, ...values: unknown[]) => Promise<unknown[]>) & {
  unsafe: (text: string) => Promise<unknown[]>;
  begin: <T>(work: (tx: FakeSql) => Promise<T>) => Promise<T>;
  end: () => Promise<void>;
  statements: string[];
};

function normalizeSql(text: string): string {
  return text.replace(/\s+/g, ' ').trim();
}

/** A postgres.js-style client that records statements, in order, into its own list and a shared log. */
function createFakeSql(
  name: string,
  log: string[],
  respond: (text: string, values: unknown[]) => unknown[] = () => [],
): FakeSql {
  const statements: string[] = [];
  const record = (text: string) => {
    statements.push(text);
    log.push(`${name}: ${text}`);
  };
  const sql = ((strings: TemplateStringsArray, ...values: unknown[]) => {
    const text = normalizeSql(strings.reduce((acc, part, index) => acc + part + (index < values.length ? `$${index + 1}` : ''), ''));
    record(text);
    return Promise.resolve(respond(text, values));
  }) as FakeSql;
  sql.unsafe = (text: string) => {
    const normalized = normalizeSql(text);
    record(normalized);
    return Promise.resolve(respond(normalized, []));
  };
  sql.begin = async (work) => {
    record('BEGIN');
    const result = await work(sql);
    record('COMMIT');
    return result;
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
};

const OWNER = 'acme-shop-test-u-1a2b3c';
const DB = 'acme-shop-test-1a2b3c';
const GOTRUE = `${OWNER}-gotrue`;
const SCHEMA_OWNER_QUERY = 'SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname = $1';

const gotrueDeclared = { name: 'gotrue', grants: { schema: 'auth', owner: true } };
const appDeclared = { name: 'app', grants: 'readwrite' };

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
    org_id: 'org_acme',
    project_id: 'proj_shop',
    env_id: 'env_1',
    backup_retention: null,
    desired_extensions: [],
    enabled_extensions: [],
    desired_roles: [],
    deleted_at: null,
    ...overrides,
  };
}

function provisionedRole(name: string, grants: string, schemaName: string | null = null) {
  return {
    id: `mdbr_${name}`,
    tenant_id: 'mdbt_1',
    name,
    grants,
    schema_name: schemaName,
    db_user: `${OWNER}-${name}`,
    credential_secret_ref: `postgres://${OWNER}-${name}:old@db.internal:5432/${DB}?sslmode=disable`,
  };
}

function createService(tenant: ReturnType<typeof buildTenant>, managedDbOverrides: Record<string, unknown> = {}) {
  const mockDb = Object.assign(
    () => Promise.resolve([]),
    { json: vi.fn(), end: vi.fn() },
  ) as unknown as import('@eve/db').Db;
  const service = new ManagedDbReconcilerService(mockDb);
  const managedDb = {
    forceReleaseStaleOperationLocks: vi.fn().mockResolvedValue([]),
    listTenantsNeedingReconciliation: vi.fn().mockResolvedValue([tenant]),
    findOrphanedTenants: vi.fn().mockResolvedValue([]),
    acquireOperationLock: vi.fn().mockResolvedValue(tenant),
    releaseOperationLock: vi.fn().mockResolvedValue(true),
    findInstanceById: vi.fn().mockResolvedValue(instance),
    transitionStatus: vi.fn().mockResolvedValue(tenant),
    failOperation: vi.fn().mockResolvedValue({ ...tenant, status: 'failed' }),
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

describe('ManagedDbReconcilerService schema-owner roles', () => {
  const originalEnv = { ...process.env };
  let log: string[];
  let adminSql: FakeSql;
  let tenantSql: FakeSql;
  let logs: string[];

  /**
   * The tenant database's answers: who owns `auth` (following the CREATE and
   * ALTER SCHEMA statements run), and the objects in it.
   */
  function tenantDb(
    schemaOwner: string | null,
    objects: Array<{ kind: string; identity: string; owner: string }> = [],
    unmovable: string[] = [],
  ) {
    let owner = schemaOwner;
    tenantSql = createFakeSql('tenant', log, (text) => {
      if (text === SCHEMA_OWNER_QUERY) return owner === null ? [] : [{ owner }];
      if (text.includes('FROM pg_class c')) return objects;
      if (text.includes('FROM pg_catalog.pg_operator o')) return unmovable.map((object) => ({ object }));
      const moved = /^(?:CREATE SCHEMA "auth" AUTHORIZATION|ALTER SCHEMA "auth" OWNER TO) "([^"]+)"$/.exec(text);
      if (moved) owner = moved[1];
      return [];
    });
  }

  beforeEach(() => {
    process.env = { ...originalEnv, DATABASE_URL: 'postgres://eve:eve@localhost:5432/eve?sslmode=disable' };
    logs = [];
    vi.spyOn(Logger.prototype, 'log').mockImplementation((message: unknown) => { logs.push(String(message)); });
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
    log = [];
    adminSql = createFakeSql('admin', log);
    tenantDb(null);
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    vi.restoreAllMocks();
  });

  function wireConnections(service: ManagedDbReconcilerService) {
    vi.spyOn(service as any, 'connectToInstance').mockImplementation(() => adminSql);
    vi.spyOn(service as any, 'connectToTenantDb').mockImplementation(() => tenantSql);
  }

  it('creates the login and a new schema it owns on a fresh tenant, with no grants in public', async () => {
    const { service, managedDb } = createService(buildTenant({ desired_roles: [appDeclared, gotrueDeclared] }));
    wireConnections(service);

    await service.reconcile();

    expect(adminSql.statements).toEqual(expect.arrayContaining([
      expect.stringMatching(new RegExp(`^CREATE ROLE "${GOTRUE}" WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 25 PASSWORD '[0-9a-f]{32}'$`)),
      `GRANT CONNECT ON DATABASE "${DB}" TO "${GOTRUE}"`,
      `GRANT "${GOTRUE}" TO CURRENT_USER`,
    ]));
    const created = tenantSql.statements.indexOf(`CREATE SCHEMA "auth" AUTHORIZATION "${GOTRUE}"`);
    expect(created).toBeGreaterThanOrEqual(0);
    // Snapshots run as the tenant owner: it may read the new schema.
    expect(tenantSql.statements.slice(created + 1, created + 3)).toEqual([
      `GRANT USAGE ON SCHEMA "auth" TO "${OWNER}"`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA "auth" TO "${OWNER}"`,
    ]);
    expect(tenantSql.statements.filter((statement) => statement.includes(`TO "${GOTRUE}"`) && statement.includes('"public"'))).toEqual([]);
    // app keeps its public grants.
    expect(tenantSql.statements).toContain(`GRANT USAGE ON SCHEMA "public" TO "${OWNER}-app"`);
    expect(managedDb.upsertTenantRole).toHaveBeenCalledWith(expect.objectContaining({
      name: 'gotrue',
      grants: 'owner',
      schema_name: 'auth',
      db_user: GOTRUE,
      credential_secret_ref: expect.stringMatching(new RegExp(`^postgres://${GOTRUE}:[0-9a-f]{32}@db\\.internal:5432/${DB}\\?sslmode=disable$`)),
    }));
    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', expect.objectContaining({ setReady: true }));
  });

  it('sets an owner role up again when its database is provisioned again', async () => {
    // A tenant revived after a destroy, or retried after a failure, whose
    // owner role is still recorded: the database may be new, so the login,
    // its CONNECT and the platform login's membership are set up again.
    const { service, managedDb } = createService(
      buildTenant({ desired_roles: [gotrueDeclared] }),
      { listTenantRoles: vi.fn().mockResolvedValue([provisionedRole('gotrue', 'owner', 'auth')]) },
    );
    wireConnections(service);

    await service.reconcile();

    expect(adminSql.statements).toEqual(expect.arrayContaining([
      expect.stringMatching(new RegExp(`^CREATE ROLE "${GOTRUE}" WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT CONNECTION LIMIT 25 PASSWORD '[0-9a-f]{32}'$`)),
      `GRANT CONNECT ON DATABASE "${DB}" TO "${GOTRUE}"`,
      `GRANT "${GOTRUE}" TO CURRENT_USER`,
    ]));
    expect(tenantSql.statements).toContain(`CREATE SCHEMA "auth" AUTHORIZATION "${GOTRUE}"`);
    expect(managedDb.upsertTenantRole).toHaveBeenCalledWith(expect.objectContaining({
      name: 'gotrue', grants: 'owner', schema_name: 'auth', credential_secret_ref: expect.stringMatching(/^postgres:\/\//),
    }));
    expect(managedDb.deleteTenantRole).not.toHaveBeenCalled();
  });

  it('hands over a schema the tenant owner owns, object by object, and logs what moved', async () => {
    tenantDb(OWNER, [
      { kind: 'routine', identity: 'auth.uid()', owner: OWNER },
      { kind: 'table', identity: 'auth.users', owner: OWNER },
      { kind: 'type', identity: 'auth.factor_type', owner: OWNER },
    ]);
    const { service, managedDb } = createService(
      buildTenant({ status: 'modifying', desired_roles: [appDeclared, gotrueDeclared] }),
      { listTenantRoles: vi.fn().mockResolvedValue([provisionedRole('app', 'readwrite')]) },
    );
    wireConnections(service);

    await service.reconcile();

    const handOver = tenantSql.statements.slice(tenantSql.statements.lastIndexOf('BEGIN'));
    expect(handOver).toEqual([
      'BEGIN',
      "SET LOCAL lock_timeout = '5s'",
      'SET LOCAL search_path = pg_catalog',
      SCHEMA_OWNER_QUERY,
      expect.stringContaining('FROM pg_class c'),
      expect.stringContaining('FROM pg_catalog.pg_operator o'),
      `ALTER SCHEMA "auth" OWNER TO "${GOTRUE}"`,
      `ALTER ROUTINE auth.uid() OWNER TO "${GOTRUE}"`,
      `ALTER TABLE auth.users OWNER TO "${GOTRUE}"`,
      `ALTER TYPE auth.factor_type OWNER TO "${GOTRUE}"`,
      `REVOKE ALL ON SCHEMA "auth" FROM PUBLIC, "${OWNER}", "${OWNER}-app"`,
      // Snapshots run as the tenant owner, which keeps read access.
      `GRANT USAGE ON SCHEMA "auth" TO "${OWNER}"`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA "auth" TO "${OWNER}"`,
      `GRANT SELECT ON ALL SEQUENCES IN SCHEMA "auth" TO "${OWNER}"`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE "${GOTRUE}" IN SCHEMA "auth" GRANT SELECT ON TABLES TO "${OWNER}"`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE "${GOTRUE}" IN SCHEMA "auth" GRANT SELECT ON SEQUENCES TO "${OWNER}"`,
      'COMMIT',
    ]);
    expect(logs.join('\n')).toMatch(/Handed schema auth of tenant mdbt_1 to gotrue: 1 routine, 1 table, 1 type/);
    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', { desiredClass: null });
  });

  it('gives the schema again on every run, and changes nothing when the role holds it', async () => {
    tenantDb(GOTRUE);
    const { service, managedDb } = createService(
      buildTenant({ status: 'modifying', desired_class: 'db.p2', desired_roles: [gotrueDeclared] }),
      { listTenantRoles: vi.fn().mockResolvedValue([provisionedRole('gotrue', 'owner', 'auth')]) },
    );
    wireConnections(service);

    await service.reconcile();

    expect(tenantSql.statements).toContain(SCHEMA_OWNER_QUERY);
    expect(tenantSql.statements.some((statement) => /^(CREATE|ALTER|REVOKE|GRANT)/.test(statement))).toBe(false);
    expect(adminSql.statements.some((statement) => statement.includes(GOTRUE) && /^(CREATE|DROP|GRANT)/.test(statement))).toBe(false);
    expect(managedDb.upsertTenantRole).not.toHaveBeenCalled();
    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', { desiredClass: null });
  });

  it('marks the tenant failed and changes nothing when another role owns the schema', async () => {
    tenantDb('stranger');
    const { service, managedDb } = createService(
      buildTenant({ status: 'modifying', desired_roles: [appDeclared, gotrueDeclared] }),
      { listTenantRoles: vi.fn().mockResolvedValue([provisionedRole('app', 'readwrite')]) },
    );
    wireConnections(service);

    await service.reconcile();

    expect(managedDb.failOperation).toHaveBeenCalledWith('mdbt_1', expect.any(String), {
      code: 'schema_owner_conflict',
      message: expect.stringMatching(/Schema "auth" is owned by "stranger"/),
    });
    expect(managedDb.transitionStatus).not.toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', expect.anything());
    expect(adminSql.statements.some((statement) => /^(CREATE|ALTER|GRANT|DROP)/.test(statement))).toBe(false);
    expect(tenantSql.statements.some((statement) => /^(CREATE|ALTER|GRANT|REVOKE)/.test(statement))).toBe(false);
    expect(managedDb.upsertTenantRole).not.toHaveBeenCalled();
  });

  it('marks the tenant failed and changes nothing when an object in the schema belongs to another role', async () => {
    tenantDb(OWNER, [{ kind: 'table', identity: 'auth.users', owner: 'stranger' }]);
    const { service, managedDb } = createService(
      buildTenant({ status: 'modifying', desired_roles: [gotrueDeclared] }),
    );
    wireConnections(service);

    await service.reconcile();

    expect(managedDb.failOperation).toHaveBeenCalledWith('mdbt_1', expect.any(String), {
      code: 'schema_owner_conflict',
      message: expect.stringMatching(/holds objects owned by "stranger"/),
    });
    expect(adminSql.statements.some((statement) => /^(CREATE|ALTER|GRANT|DROP)/.test(statement))).toBe(false);
    expect(managedDb.upsertTenantRole).not.toHaveBeenCalled();
  });

  it('marks the tenant failed and changes nothing when the schema holds an object a hand-over does not move', async () => {
    tenantDb(OWNER, [{ kind: 'table', identity: 'auth.users', owner: OWNER }], ['operator auth.===(integer,integer)']);
    const { service, managedDb } = createService(
      buildTenant({ status: 'modifying', desired_roles: [gotrueDeclared] }),
    );
    wireConnections(service);

    await service.reconcile();

    expect(managedDb.failOperation).toHaveBeenCalledWith('mdbt_1', expect.any(String), {
      code: 'schema_owner_conflict',
      message: expect.stringMatching(/does not move: operator auth\.===\(integer,integer\); nothing was handed over/),
    });
    expect(adminSql.statements.some((statement) => /^(CREATE|ALTER|GRANT|DROP)/.test(statement))).toBe(false);
    expect(tenantSql.statements.some((statement) => /^(CREATE|ALTER|GRANT|REVOKE)/.test(statement))).toBe(false);
    expect(managedDb.upsertTenantRole).not.toHaveBeenCalled();
  });

  it('hands the schema back to the tenant owner before dropping a removed owner role', async () => {
    tenantDb(GOTRUE);
    const { service, managedDb } = createService(
      buildTenant({ status: 'modifying', desired_roles: [appDeclared] }),
      {
        listTenantRoles: vi.fn().mockResolvedValue([
          provisionedRole('app', 'readwrite'),
          provisionedRole('gotrue', 'owner', 'auth'),
        ]),
      },
    );
    wireConnections(service);

    await service.reconcile();

    // The login stops signing in and its sessions end before anything moves,
    // so nothing it commits meanwhile is dropped or keeps the login.
    const noLogin = log.indexOf(`tenant: ALTER ROLE "${GOTRUE}" NOLOGIN`);
    const terminate = log.findIndex((entry) => entry.startsWith('tenant: SELECT pg_catalog.pg_terminate_backend(pid'));
    const handBack = log.indexOf(`tenant: ALTER SCHEMA "auth" OWNER TO "${OWNER}"`);
    const reassign = log.indexOf(`tenant: REASSIGN OWNED BY "${GOTRUE}" TO "${OWNER}"`);
    const dropOwned = log.indexOf(`tenant: DROP OWNED BY "${GOTRUE}"`);
    const dropRole = log.indexOf(`admin: DROP ROLE IF EXISTS "${GOTRUE}"`);
    const steps = [noLogin, terminate, handBack, reassign, dropOwned, dropRole];
    expect(noLogin).toBeGreaterThanOrEqual(0);
    expect(steps).toEqual([...steps].sort((a, b) => a - b));
    expect(new Set(steps).size).toBe(6);
    // No public revokes for a role that never had public grants.
    expect(tenantSql.statements.some((statement) => statement.includes('"public"') && statement.includes(GOTRUE))).toBe(false);
    expect(managedDb.deleteTenantRole).toHaveBeenCalledWith('mdbt_1', 'gotrue');
    expect(managedDb.transitionStatus).toHaveBeenCalledWith('mdbt_1', expect.any(String), 'ready', { desiredClass: null });
  });

  it('moves a schema from a role being removed to the role that replaces it in the same run', async () => {
    tenantDb(`${OWNER}-gotrue_old`);
    const { service, managedDb } = createService(
      buildTenant({ status: 'modifying', desired_roles: [gotrueDeclared] }),
      { listTenantRoles: vi.fn().mockResolvedValue([provisionedRole('gotrue_old', 'owner', 'auth')]) },
    );
    wireConnections(service);

    await service.reconcile();

    expect(managedDb.failOperation).not.toHaveBeenCalled();
    const handBack = log.indexOf(`tenant: ALTER SCHEMA "auth" OWNER TO "${OWNER}"`);
    const dropOld = log.indexOf(`admin: DROP ROLE IF EXISTS "${OWNER}-gotrue_old"`);
    const createNew = log.findIndex((entry) => entry.startsWith(`admin: CREATE ROLE "${GOTRUE}"`));
    expect(handBack).toBeGreaterThanOrEqual(0);
    expect(dropOld).toBeGreaterThan(handBack);
    expect(createNew).toBeGreaterThan(dropOld);
    expect(managedDb.upsertTenantRole).toHaveBeenCalledWith(expect.objectContaining({ name: 'gotrue', schema_name: 'auth' }));
  });
});
