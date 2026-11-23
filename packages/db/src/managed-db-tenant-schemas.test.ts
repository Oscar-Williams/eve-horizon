/**
 * Schema-owner roles against a real Postgres: a tenant database, its owner, a
 * schema-owner role, a `public` data role and an unrelated role, and a
 * platform login that is not a superuser (as on Cloud SQL) and is a member of
 * the owner and of the schema-owner role, as the reconciler makes it. The
 * helpers run as that platform login.
 */

import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import postgres from 'postgres';
import { spawn } from 'child_process';
import type { Readable } from 'stream';
import { executeSnapshot, type SnapshotUploadTarget } from '@eve/shared';
import {
  ManagedDbSchemaConflictError,
  checkManagedDbSchemaClaim,
  claimManagedDbSchema,
  managedDbSchemaOwner,
  releaseManagedDbSchema,
} from './managed-db-tenant-schemas.js';
import type { Db } from './client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 8);
const dbName = `eve_tenant_${suffix}`;
const owner = `acme_shop_${suffix}`;
const gotrue = `${owner}-gotrue`;
const app = `${owner}-app`;
const stranger = `stranger_${suffix}`;
const platform = `platform_${suffix}`;

const target = { dbName, schema: 'auth', roleUser: gotrue, ownerUser: owner };

/**
 * Objects of kinds a hand-over does not move, each owned by the tenant owner
 * (made as the superuser where Postgres requires it): [kind, statements].
 */
const UNMOVABLE: Array<[string, string]> = [
  ['operator', `
    CREATE FUNCTION auth.int_eq(int, int) RETURNS boolean LANGUAGE sql IMMUTABLE AS 'SELECT $1 = $2';
    CREATE OPERATOR auth.=== (LEFTARG = int, RIGHTARG = int, FUNCTION = auth.int_eq);
    ALTER FUNCTION auth.int_eq(int, int) OWNER TO "${owner}";
    ALTER OPERATOR auth.=== (int, int) OWNER TO "${owner}";`],
  ['operator class', `
    CREATE OPERATOR CLASS auth.int_hash FOR TYPE int USING hash AS OPERATOR 1 =, FUNCTION 1 hashint4(int);
    ALTER OPERATOR CLASS auth.int_hash USING hash OWNER TO "${owner}";`],
  ['operator family', `
    CREATE OPERATOR FAMILY auth.int_ops USING btree;
    ALTER OPERATOR FAMILY auth.int_ops USING btree OWNER TO "${owner}";`],
  ['collation', `
    CREATE COLLATION auth.c_copy FROM "C";
    ALTER COLLATION auth.c_copy OWNER TO "${owner}";`],
  ['text search configuration', `
    CREATE TEXT SEARCH CONFIGURATION auth.simple_copy (COPY = pg_catalog.simple);
    ALTER TEXT SEARCH CONFIGURATION auth.simple_copy OWNER TO "${owner}";`],
  ['text search dictionary', `
    CREATE TEXT SEARCH DICTIONARY auth.simple_dict (TEMPLATE = pg_catalog.simple);
    ALTER TEXT SEARCH DICTIONARY auth.simple_dict OWNER TO "${owner}";`],
  ['conversion', `
    CREATE CONVERSION auth.latin1_utf8 FOR 'LATIN1' TO 'UTF8' FROM iso8859_1_to_utf8;
    ALTER CONVERSION auth.latin1_utf8 OWNER TO "${owner}";`],
  ['statistics object', `
    CREATE STATISTICS auth.users_stats ON id, email FROM auth.users;
    ALTER STATISTICS auth.users_stats OWNER TO "${owner}";`],
  ['ordered-set aggregate', `
    CREATE AGGREGATE auth.pct(float8 ORDER BY float8) (
      SFUNC = ordered_set_transition, STYPE = internal, FINALFUNC = percentile_disc_final, FINALFUNC_EXTRA);
    ALTER AGGREGATE auth.pct(float8 ORDER BY float8) OWNER TO "${owner}";`],
];

function urlFor(user: string | null, database: string): string {
  const url = new URL(testDbUrl!);
  if (user) {
    url.username = user;
    url.password = 'pw';
  }
  url.pathname = `/${database}`;
  return url.toString();
}

/**
 * A tenant database session as Eve opens one: search_path pinned to
 * pg_catalog at startup, and no startup type query, so arrays come back as
 * text.
 */
function pinnedTenantSession(user: string): Db {
  return postgres(urlFor(user, dbName), { fetch_types: false, connection: { search_path: 'pg_catalog' } });
}

/** A session of a role in the tenant database, through psql, that runs `script`; resolves to psql's exit code. */
function roleSession(user: string, script: string): Promise<number> {
  const url = new URL(testDbUrl!);
  const child = spawn('psql', [
    `--host=${url.hostname}`, `--port=${url.port || '5432'}`, `--username=${user}`, '--no-password',
    '--quiet', '--set=ON_ERROR_STOP=1', '--command', script, dbName,
  ], { env: { ...process.env, PGPASSWORD: 'pw' }, stdio: 'ignore' });
  return new Promise((resolve) => child.on('exit', (code) => resolve(code ?? -1)));
}

async function waitFor(check: () => Promise<boolean>, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!(await check())) {
    if (Date.now() > deadline) throw new Error('timed out waiting');
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

/** A snapshot of the tenant database as Eve takes one: pg_dump as the tenant owner, into a store that counts the bytes. */
async function snapshotAsOwner(): Promise<number> {
  const url = new URL(testDbUrl!);
  const store = {
    async uploadStream(_bucket: string, _key: string, body: Readable): Promise<number> {
      let size = 0;
      for await (const chunk of body) size += (chunk as Buffer).length;
      return size;
    },
  } as unknown as SnapshotUploadTarget['client'];
  const result = await executeSnapshot(
    { host: url.hostname, port: Number(url.port) || 5432, username: owner, password: 'pw', database: dbName },
    { client: store, bucket: 'snapshots', key: 'tenant.dump' },
    { timeoutMs: 60_000 },
  );
  return result.sizeBytes;
}

describe('schema-owner roles in a tenant database', () => {
  let admin: Db;
  let superTenant: Db;
  let tenant: Db;

  /** Run statements as a role inside the tenant database (SET ROLE drops the superuser's rights). */
  async function as<T>(role: string, work: (tx: Db) => Promise<T>): Promise<T> {
    return superTenant.begin(async (rawTx) => {
      const tx = rawTx as unknown as Db;
      await tx.unsafe(`SET LOCAL ROLE "${role}"`);
      return work(tx);
    }) as Promise<T>;
  }

  async function owners(): Promise<Record<string, string>> {
    const rows = await superTenant<{ name: string; owner: string }[]>`
      SELECT c.relname AS name, pg_get_userbyid(c.relowner) AS owner
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
      WHERE n.nspname = 'auth' AND c.relkind IN ('r', 'S', 'v')
      UNION ALL
      SELECT p.proname, pg_get_userbyid(p.proowner)
      FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'auth'
      UNION ALL
      SELECT t.typname, pg_get_userbyid(t.typowner)
      FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
      WHERE n.nspname = 'auth' AND t.typtype IN ('e', 'd')
      UNION ALL
      SELECT '(schema)', pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = 'auth'
    `;
    return Object.fromEntries(rows.map((row) => [row.name, row.owner]));
  }

  /** An `auth` schema the tenant owner made, as GoTrue logged in as the owner did. */
  async function ownerMadeAuth(): Promise<void> {
    await as(owner, async (tx) => {
      await tx.unsafe(`
        CREATE SCHEMA auth;
        CREATE TABLE auth.users (id serial PRIMARY KEY, email text NOT NULL);
        INSERT INTO auth.users (email) VALUES ('alice@eve.example'), ('bob@eve.example');
        CREATE SEQUENCE auth.refresh_token_id_seq;
        CREATE TYPE auth.factor_type AS ENUM ('totp', 'webauthn');
        CREATE DOMAIN auth.email AS text CHECK (VALUE LIKE '%@%');
        CREATE FUNCTION auth.uid() RETURNS integer LANGUAGE sql STABLE AS 'SELECT 1';
        CREATE VIEW auth.emails AS SELECT email FROM auth.users;
        GRANT USAGE ON SCHEMA auth TO "${app}";
        GRANT SELECT ON auth.users TO "${app}";
      `);
    });
  }

  beforeAll(async () => {
    admin = postgres(testDbUrl!);
    for (const role of [owner, gotrue, app, stranger]) {
      await admin.unsafe(`CREATE ROLE "${role}" LOGIN NOINHERIT PASSWORD 'pw'`);
    }
    await admin.unsafe(`CREATE ROLE "${platform}" LOGIN CREATEROLE PASSWORD 'pw'`);
    await admin.unsafe(`CREATE DATABASE "${dbName}" OWNER "${owner}"`);
    // As the reconciler does: the platform login is a member of the owner
    // and of the schema-owner role.
    await admin.unsafe(`GRANT "${owner}" TO "${platform}"`);
    await admin.unsafe(`GRANT "${gotrue}" TO "${platform}"`);
    superTenant = postgres(urlFor(null, dbName));
    tenant = pinnedTenantSession(platform);
  });

  afterAll(async () => {
    await tenant?.end();
    await superTenant?.end();
    await admin.unsafe(`DROP DATABASE IF EXISTS "${dbName}"`);
    for (const role of [gotrue, app, stranger, owner, platform]) {
      await admin.unsafe(`DROP ROLE IF EXISTS "${role}"`);
    }
    await admin.end();
  });

  beforeEach(async () => {
    await superTenant.unsafe('DROP SCHEMA IF EXISTS auth CASCADE');
    await superTenant.unsafe(`
      DROP TABLE IF EXISTS public.ledger;
      DROP FUNCTION IF EXISTS public.whoami();
    `);
    // Postgres 15 and later: public grants CREATE to no one by default.
    await superTenant.unsafe('REVOKE CREATE ON SCHEMA public FROM PUBLIC');
    // A hand-back leaves the role unable to sign in.
    await admin.unsafe(`ALTER ROLE "${gotrue}" LOGIN`);
  });

  it('runs as a platform login that is not a superuser', async () => {
    const [row] = await tenant<{ rolsuper: boolean }[]>`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`;
    expect(row.rolsuper).toBe(false);
  });

  describe('a fresh tenant', () => {
    it('creates the schema owned by the role', async () => {
      await expect(claimManagedDbSchema(tenant, target)).resolves.toEqual({ action: 'created' });
      expect(await managedDbSchemaOwner(tenant, 'auth')).toBe(gotrue);
    });

    it('lets the role create a table in its schema and not in public', async () => {
      await claimManagedDbSchema(tenant, target);
      await as(gotrue, (tx) => tx.unsafe('CREATE TABLE auth.sessions (id int)'));
      await expect(as(gotrue, (tx) => tx.unsafe('CREATE TABLE public.sessions (id int)')))
        .rejects.toThrow(/permission denied/);
    });

    it('gives the other roles nothing in the schema, and the tenant owner read access only', async () => {
      await claimManagedDbSchema(tenant, target);
      await as(gotrue, (tx) => tx.unsafe('CREATE TABLE auth.sessions (id int); INSERT INTO auth.sessions VALUES (1)'));
      await expect(as(app, (tx) => tx.unsafe('SELECT * FROM auth.sessions'))).rejects.toThrow(/permission denied/);
      const rows = await as(owner, (tx) => tx.unsafe('SELECT id FROM auth.sessions'));
      expect(rows.map((row) => row.id)).toEqual([1]);
      await expect(as(owner, (tx) => tx.unsafe('INSERT INTO auth.sessions VALUES (2)'))).rejects.toThrow(/permission denied/);
      await expect(as(owner, (tx) => tx.unsafe('CREATE TABLE auth.extra (id int)'))).rejects.toThrow(/permission denied/);
    });

    it('lets a snapshot, which runs as the tenant owner, dump what the role makes in the schema', async () => {
      await claimManagedDbSchema(tenant, target);
      await as(gotrue, (tx) => tx.unsafe(`
        CREATE TABLE auth.sessions (id serial PRIMARY KEY, token text);
        INSERT INTO auth.sessions (token) VALUES ('t1');
        CREATE SEQUENCE auth.audit_seq;
      `));
      await expect(snapshotAsOwner()).resolves.toBeGreaterThan(0);
    });
  });

  describe('a schema the tenant owner owns', () => {
    it('hands the schema and every object in it to the role, with the rows intact', async () => {
      await ownerMadeAuth();

      const claim = await claimManagedDbSchema(tenant, target, { revokeFrom: [owner, app] });

      expect(claim).toEqual({
        action: 'handed_over',
        objects: { table: 1, sequence: 1, type: 1, domain: 1, routine: 1, view: 1 },
      });
      expect(await owners()).toEqual({
        '(schema)': gotrue,
        users: gotrue,
        users_id_seq: gotrue,
        refresh_token_id_seq: gotrue,
        emails: gotrue,
        uid: gotrue,
        factor_type: gotrue,
        email: gotrue,
      });
      const rows = await as(gotrue, (tx) => tx.unsafe('SELECT email FROM auth.users ORDER BY id'));
      expect(rows.map((row) => row.email)).toEqual(['alice@eve.example', 'bob@eve.example']);
      // The role can now change what it owns.
      await as(gotrue, (tx) => tx.unsafe('ALTER TABLE auth.users ADD COLUMN phone text'));
    });

    it('lets a snapshot as the tenant owner dump the schema after the hand-over, and what the role adds later', async () => {
      await ownerMadeAuth();
      await claimManagedDbSchema(tenant, target, { revokeFrom: [owner, app] });
      await as(gotrue, (tx) => tx.unsafe('CREATE TABLE auth.sessions (id serial PRIMARY KEY); INSERT INTO auth.sessions DEFAULT VALUES'));
      const rows = await as(owner, (tx) => tx.unsafe('SELECT count(*)::int AS n FROM auth.users'));
      expect(rows[0].n).toBe(2);
      await expect(snapshotAsOwner()).resolves.toBeGreaterThan(0);
    });

    it('takes back what the other roles of the tenant were given in the schema', async () => {
      await ownerMadeAuth();
      await claimManagedDbSchema(tenant, target, { revokeFrom: [owner, app] });
      await expect(as(app, (tx) => tx.unsafe('SELECT * FROM auth.users'))).rejects.toThrow(/permission denied/);
    });

    it('changes nothing on a second run', async () => {
      await ownerMadeAuth();
      await claimManagedDbSchema(tenant, target);
      const before = await owners();
      await expect(claimManagedDbSchema(tenant, target)).resolves.toEqual({ action: 'unchanged' });
      expect(await owners()).toEqual(before);
    });

    it('refuses, and changes nothing, when an object in it belongs to another role', async () => {
      await ownerMadeAuth();
      await superTenant.unsafe(`ALTER TABLE auth.users OWNER TO "${stranger}"`);
      const before = await owners();
      await expect(claimManagedDbSchema(tenant, target)).rejects.toBeInstanceOf(ManagedDbSchemaConflictError);
      await expect(claimManagedDbSchema(tenant, target)).rejects.toThrow(new RegExp(stranger));
      expect(await owners()).toEqual(before);
    });

    it.each(UNMOVABLE)('refuses, and changes nothing, when it holds an object a hand-over does not move: %s', async (kind, statements) => {
      await ownerMadeAuth();
      await superTenant.unsafe(statements);
      const before = await owners();
      const refusal = new RegExp(`does not move: .*${kind} auth\\.`);
      await expect(checkManagedDbSchemaClaim(tenant, target)).rejects.toThrow(refusal);
      const claim = claimManagedDbSchema(tenant, target);
      await expect(claim).rejects.toBeInstanceOf(ManagedDbSchemaConflictError);
      await expect(claim).rejects.toThrow(refusal);
      expect(await owners()).toEqual(before);
    });
  });

  it('refuses, and changes nothing, when another role owns the schema', async () => {
    await superTenant.unsafe(`CREATE SCHEMA auth AUTHORIZATION "${stranger}"`);
    await expect(claimManagedDbSchema(tenant, target)).rejects.toBeInstanceOf(ManagedDbSchemaConflictError);
    await expect(claimManagedDbSchema(tenant, target)).rejects.toThrow(/owned by "stranger_/);
    expect(await managedDbSchemaOwner(superTenant, 'auth')).toBe(stranger);
  });

  describe('removal', () => {
    it('hands the schema and its objects back to the tenant owner, so the login can be dropped', async () => {
      await ownerMadeAuth();
      await claimManagedDbSchema(tenant, target);
      await as(gotrue, (tx) => tx.unsafe('CREATE TABLE auth.sessions (id int); INSERT INTO auth.sessions VALUES (1)'));

      await releaseManagedDbSchema(tenant, target);

      const after = await owners();
      expect(new Set(Object.values(after))).toEqual(new Set([owner]));
      expect(after.sessions).toBe(owner);
      const rows = await as(owner, (tx) => tx.unsafe('SELECT count(*)::int AS n FROM auth.users'));
      expect(rows[0].n).toBe(2);

      // Nothing in the tenant database depends on the login any more.
      const [{ dependents }] = await superTenant<{ dependents: number }[]>`
        SELECT count(*)::int AS dependents FROM pg_shdepend
        WHERE refobjid = (SELECT oid FROM pg_roles WHERE rolname = ${gotrue})
          AND dbid = (SELECT oid FROM pg_database WHERE datname = ${dbName})
      `;
      expect(dependents).toBe(0);
      // The default privileges that kept the schema readable for snapshots went with it.
      const [{ defaults }] = await superTenant<{ defaults: number }[]>`
        SELECT count(*)::int AS defaults FROM pg_default_acl
        WHERE defaclrole = (SELECT oid FROM pg_roles WHERE rolname = ${gotrue})
      `;
      expect(defaults).toBe(0);
    });

    it('makes the SECURITY DEFINER functions and procedures the role made run as their caller, in its schema and elsewhere', async () => {
      await claimManagedDbSchema(tenant, target);
      // As on Postgres 14 defaults, where every role may create in public.
      await superTenant.unsafe('GRANT CREATE ON SCHEMA public TO PUBLIC');
      await as(gotrue, (tx) => tx.unsafe(`
        CREATE FUNCTION auth.whoami() RETURNS name LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user';
        CREATE PROCEDURE auth.touch() LANGUAGE sql SECURITY DEFINER AS 'SELECT 1';
        CREATE FUNCTION public.whoami() RETURNS name LANGUAGE sql SECURITY DEFINER AS 'SELECT current_user';
      `));

      await releaseManagedDbSchema(tenant, target);

      const definers = await superTenant<{ routine: string }[]>`
        SELECT p.oid::regprocedure::text AS routine FROM pg_proc p
        WHERE p.prosecdef AND p.proowner = (SELECT oid FROM pg_roles WHERE rolname = ${owner})
      `;
      expect(definers).toEqual([]);
      // Should the tenant owner grant one again, it runs as whoever calls it.
      await as(owner, (tx) => tx.unsafe(`GRANT USAGE ON SCHEMA auth TO "${app}"; GRANT EXECUTE ON FUNCTION auth.whoami() TO "${app}"`));
      const [row] = await as(app, (tx) => tx.unsafe('SELECT auth.whoami() AS who'));
      expect(row.who).toBe(app);
    });

    it('takes back what the role granted on its schema and what it owned, so no other login reaches them as the tenant owner', async () => {
      await superTenant.unsafe(`
        CREATE TABLE public.ledger (entry text);
        INSERT INTO public.ledger VALUES ('owner only');
        ALTER TABLE public.ledger OWNER TO "${owner}";
      `);
      await claimManagedDbSchema(tenant, target, { revokeFrom: [owner, app] });
      // The role cannot read the owner's ledger; a view reads it with the rights of the view's owner.
      await as(gotrue, (tx) => tx.unsafe(`
        CREATE VIEW auth.ledger AS SELECT entry FROM public.ledger;
        CREATE TABLE auth.sessions (id int, token text);
        CREATE SEQUENCE auth.session_ids;
        CREATE TYPE auth.level AS ENUM ('aal1', 'aal2');
        CREATE FUNCTION auth.uid() RETURNS integer LANGUAGE sql STABLE AS 'SELECT 1';
        GRANT USAGE ON SCHEMA auth TO PUBLIC;
        GRANT SELECT ON auth.ledger TO "${app}" WITH GRANT OPTION;
        GRANT SELECT (token) ON auth.sessions TO "${app}";
        GRANT USAGE ON SEQUENCE auth.session_ids TO "${app}";
        GRANT USAGE ON TYPE auth.level TO "${app}";
      `));
      await as(app, (tx) => tx.unsafe(`GRANT SELECT ON auth.ledger TO "${stranger}"`));
      await expect(as(app, (tx) => tx.unsafe('SELECT * FROM auth.ledger'))).rejects.toThrow(/permission denied for table ledger/);

      await releaseManagedDbSchema(tenant, target);

      for (const login of [app, stranger]) {
        await expect(as(login, (tx) => tx.unsafe('SELECT * FROM auth.ledger'))).rejects.toThrow(/permission denied/);
        await expect(as(login, (tx) => tx.unsafe('SELECT auth.uid()'))).rejects.toThrow(/permission denied/);
      }
      // Nothing on the schema, or in it, is granted to anyone but the tenant owner.
      const grants = await superTenant<{ object: string; grantee: string }[]>`
        SELECT o.object, CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_get_userbyid(a.grantee)::text END AS grantee
        FROM (
          SELECT 'schema auth' AS object, nspacl AS acl FROM pg_namespace WHERE nspname = 'auth'
          UNION ALL
          SELECT 'relation ' || c.relname, c.relacl FROM pg_class c WHERE c.relnamespace = 'auth'::regnamespace
          UNION ALL
          SELECT 'column ' || c.relname || '.' || t.attname, t.attacl
          FROM pg_attribute t JOIN pg_class c ON c.oid = t.attrelid WHERE c.relnamespace = 'auth'::regnamespace
          UNION ALL
          SELECT 'routine ' || p.proname, coalesce(p.proacl, acldefault('f', p.proowner))
          FROM pg_proc p WHERE p.pronamespace = 'auth'::regnamespace
          UNION ALL
          SELECT 'type ' || y.typname, coalesce(y.typacl, acldefault('T', y.typowner))
          FROM pg_type y WHERE y.typnamespace = 'auth'::regnamespace AND y.typrelid = 0 AND y.typelem = 0
        ) o, aclexplode(o.acl) a
        WHERE a.grantee <> (SELECT oid FROM pg_roles WHERE rolname = ${owner})
        ORDER BY 1, 2
      `;
      expect(grants).toEqual([]);
    });

    it('closes the role\'s sessions and refuses new ones first, so nothing it commits meanwhile is lost or keeps the login', async () => {
      await ownerMadeAuth();
      await claimManagedDbSchema(tenant, target);
      // GoTrue mid-migration, in a session of its own (psql, so the server
      // ending it is seen plainly): a table made, not yet committed, while
      // the hand-back starts.
      const session = roleSession(gotrue, 'BEGIN; CREATE TABLE auth.late (id int); SELECT pg_sleep(2); COMMIT;');
      await waitFor(async () => {
        const [row] = await superTenant<{ n: number }[]>`
          SELECT count(*)::int AS n FROM pg_stat_activity WHERE usename = ${gotrue} AND wait_event = 'PgSleep'
        `;
        return row.n === 1;
      });

      await releaseManagedDbSchema(tenant, target);

      // Only a session that outlived the hand-back could commit its table.
      expect(await session).not.toBe(0);

      const [state] = await superTenant<{ late: string | null; can_login: boolean; sessions: number; dependents: number }[]>`
        SELECT to_regclass('auth.late')::text AS late,
               (SELECT rolcanlogin FROM pg_roles WHERE rolname = ${gotrue}) AS can_login,
               (SELECT count(*)::int FROM pg_stat_activity WHERE usename = ${gotrue}) AS sessions,
               (SELECT count(*)::int FROM pg_shdepend
                WHERE refobjid = (SELECT oid FROM pg_roles WHERE rolname = ${gotrue})
                  AND dbid = (SELECT oid FROM pg_database WHERE datname = ${dbName})) AS dependents
      `;
      expect(state).toEqual({ late: null, can_login: false, sessions: 0, dependents: 0 });
      const again = postgres(urlFor(gotrue, dbName), { max: 1, onnotice: () => {} });
      try {
        await expect(again`SELECT 1`).rejects.toThrow(/not permitted to log in/);
      } finally {
        await again.end({ timeout: 0 }).catch(() => {});
      }
    }, 20_000);

    it('moves nothing and keeps the login unable to sign in when the hand-back fails, and a later run hands back', async () => {
      await ownerMadeAuth();
      await claimManagedDbSchema(tenant, target);
      const before = await owners();
      // A snapshot holds a lock on a table for longer than the hand-back waits.
      await as(owner, async (tx) => {
        await tx.unsafe('SELECT count(*) FROM auth.users');
        await expect(releaseManagedDbSchema(tenant, target)).rejects.toThrow(/lock timeout/);
      });
      expect(await owners()).toEqual(before);
      // The role is being removed, so it stays signed out until the hand-back succeeds.
      const [{ can_login }] = await superTenant<{ can_login: boolean }[]>`
        SELECT rolcanlogin AS can_login FROM pg_roles WHERE rolname = ${gotrue}
      `;
      expect(can_login).toBe(false);

      await releaseManagedDbSchema(tenant, target);
      expect(new Set(Object.values(await owners()))).toEqual(new Set([owner]));
    }, 20_000);

    it('drops nothing when the role has no schema', async () => {
      await expect(releaseManagedDbSchema(tenant, target)).resolves.toBeUndefined();
      expect(await managedDbSchemaOwner(tenant, 'auth')).toBeNull();
    });
  });

  describe('a session whose search path puts a tenant schema before pg_catalog', () => {
    // A session Eve did not pin: the tenant owner may set its database's
    // search_path and name a function like a built-in, which would then run
    // as the platform login. The decoy records each call.
    let shadowed: Db;

    async function decoyCalls(): Promise<number> {
      const [row] = await superTenant<{ n: number }[]>`SELECT count(*)::int AS n FROM decoy.calls`;
      return row.n;
    }

    beforeEach(async () => {
      await superTenant.unsafe('DROP SCHEMA IF EXISTS decoy CASCADE');
      await as(owner, (tx) => tx.unsafe(`
        CREATE SCHEMA decoy;
        CREATE TABLE decoy.calls (called_by name);
        CREATE FUNCTION decoy.pg_get_userbyid(oid) RETURNS name LANGUAGE sql AS $$
          INSERT INTO decoy.calls VALUES (current_user);
          SELECT 'decoy'::name;
        $$;
      `));
      shadowed = postgres(urlFor(platform, dbName), { fetch_types: false, connection: { search_path: 'decoy, pg_catalog' } });
    });

    afterEach(async () => {
      await shadowed.end();
      await superTenant.unsafe('DROP SCHEMA IF EXISTS decoy CASCADE');
    });

    it('reads the owner of a schema from the catalog', async () => {
      await claimManagedDbSchema(tenant, target);
      expect(await managedDbSchemaOwner(shadowed, 'auth')).toBe(gotrue);
      expect(await decoyCalls()).toBe(0);
    });

    it('hands the schema back to the tenant owner', async () => {
      await ownerMadeAuth();
      await claimManagedDbSchema(tenant, target);
      await releaseManagedDbSchema(shadowed, target);
      expect(new Set(Object.values(await owners()))).toEqual(new Set([owner]));
      expect(await decoyCalls()).toBe(0);
    });
  });
});
