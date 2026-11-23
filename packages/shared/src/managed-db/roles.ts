import { quotePostgresIdentifier } from './extensions.js';

// ---------------------------------------------------------------------------
// Declarable tenant roles
// ---------------------------------------------------------------------------
//
// A managed DB tenant always has one owner login (managed_db_tenants.db_user).
// The manifest may additionally declare least-privilege runtime logins:
//
//   x-eve.managed.roles:
//     - { name: app,     grants: readwrite }
//     - { name: reports, grants: readonly }
//     - { name: gotrue,  grants: { schema: auth, owner: true } }
//
// Each declared role becomes a Postgres LOGIN role named
// `<tenant db_user>-<name>`. `readwrite` and `readonly` grant data access in
// the tenant database's `public` schema. A schema-owner role owns one named
// schema instead (DDL there, and no grants of its own in `public`, beyond what
// PUBLIC holds): provisioned roles of that kind are stored with
// `grants = 'owner'` and the schema in `schema_name`.
// The helpers below are pure so the reconciler's SQL can be unit-tested
// without a database.

export const MANAGED_DB_ROLE_NAME_PATTERN = /^[a-z][a-z0-9_]{0,15}$/;

/**
 * Declared roles per managed database. Each is a login with its own
 * connection limit, so the cap keeps one tenant's logins within reach of the
 * database-wide limit its class sets.
 */
export const MANAGED_DB_MAX_ROLES = 8;

export const MANAGED_DB_ROLE_GRANTS = ['readwrite', 'readonly'] as const;

export type ManagedDbRoleGrants = (typeof MANAGED_DB_ROLE_GRANTS)[number];

/** `grants` of a role that owns one schema of the tenant database. */
export interface ManagedDbSchemaOwnerGrant {
  schema: string;
  owner: true;
}

/** What a declared role is granted: data access in `public`, or one schema of its own. */
export type ManagedDbRoleGrantSpec = ManagedDbRoleGrants | ManagedDbSchemaOwnerGrant;

export interface ManagedDbRoleDeclaration {
  name: string;
  grants: ManagedDbRoleGrantSpec;
}

/** The stored `grants` of a provisioned schema-owner role; its schema is in `schema_name`. */
export const MANAGED_DB_SCHEMA_OWNER_GRANTS = 'owner';

/** A schema a role may own: a plain, unquoted Postgres identifier. */
export const MANAGED_DB_SCHEMA_NAME_PATTERN = /^[a-z_][a-z0-9_]{0,62}$/;

export function isManagedDbRoleGrants(value: unknown): value is ManagedDbRoleGrants {
  return typeof value === 'string' && (MANAGED_DB_ROLE_GRANTS as readonly string[]).includes(value);
}

/**
 * Why a role cannot own the named schema, or null when it can. `public` is
 * shared by every role; `pg_*` and `information_schema` belong to Postgres.
 */
export function managedDbOwnedSchemaError(schema: unknown): string | null {
  if (typeof schema !== 'string' || !MANAGED_DB_SCHEMA_NAME_PATTERN.test(schema)) {
    return 'must be a plain lower-case identifier: [a-z_][a-z0-9_]*, at most 63 characters, no quotes or dots';
  }
  if (schema === 'public') return 'cannot be owned by a role: every role of the database shares public';
  if (schema.startsWith('pg_') || schema === 'information_schema') return 'is reserved for Postgres';
  return null;
}

export function isManagedDbSchemaOwnerGrant(value: unknown): value is ManagedDbSchemaOwnerGrant {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const keys = Object.keys(value);
  const grant = value as { schema?: unknown; owner?: unknown };
  return keys.length === 2 && grant.owner === true && managedDbOwnedSchemaError(grant.schema) === null;
}

/**
 * The schema a declared role (an owner grant) or a provisioned role
 * (`grants = 'owner'`, `schema_name`) owns; null for `public` data roles.
 */
export function managedDbRoleOwnedSchema(role: { grants: unknown; schema_name?: string | null }): string | null {
  if (isManagedDbSchemaOwnerGrant(role.grants)) return role.grants.schema;
  if (role.grants === MANAGED_DB_SCHEMA_OWNER_GRANTS) return role.schema_name ?? null;
  return null;
}

/**
 * Normalize a list of role declarations (manifest input or the JSONB
 * `desired_roles` column): drop malformed entries, dedupe by name (first
 * wins) and by owned schema (first owner wins), and sort by name so
 * persisted intent is stable.
 */
export function normalizeManagedDbRoles(input: unknown): ManagedDbRoleDeclaration[] {
  if (!Array.isArray(input)) return [];
  const byName = new Map<string, ManagedDbRoleDeclaration>();
  const ownedSchemas = new Set<string>();
  for (const entry of input) {
    if (!entry || typeof entry !== 'object') continue;
    const { name, grants } = entry as { name?: unknown; grants?: unknown };
    if (typeof name !== 'string' || !MANAGED_DB_ROLE_NAME_PATTERN.test(name)) continue;
    if (byName.has(name)) continue;
    if (isManagedDbRoleGrants(grants)) {
      byName.set(name, { name, grants });
    } else if (isManagedDbSchemaOwnerGrant(grants) && !ownedSchemas.has(grants.schema)) {
      ownedSchemas.add(grants.schema);
      byName.set(name, { name, grants: { schema: grants.schema, owner: true } });
    }
  }
  return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
}

// ---------------------------------------------------------------------------
// Desired vs provisioned diff
// ---------------------------------------------------------------------------

export interface ManagedDbProvisionedRole {
  name: string;
  grants: string;
  /** The owned schema of a schema-owner role (`grants = 'owner'`). */
  schema_name?: string | null;
}

export interface ManagedDbRoleDiff<TProvisioned extends ManagedDbProvisionedRole = ManagedDbProvisionedRole> {
  /** Declared in the manifest but not yet provisioned (or provisioned as another kind). */
  create: ManagedDbRoleDeclaration[];
  /** Provisioned with different `public` grants than declared. */
  regrant: ManagedDbRoleDeclaration[];
  /** Provisioned but no longer declared (or declared as another kind). */
  drop: TProvisioned[];
}

/** One string per grant: `readwrite`, `readonly`, or `owner:<schema>`. */
function grantKey(role: { grants: unknown; schema_name?: string | null }): string {
  const schema = managedDbRoleOwnedSchema(role);
  return schema === null ? String(role.grants) : `${MANAGED_DB_SCHEMA_OWNER_GRANTS}:${schema}`;
}

/**
 * Roles to create, regrant and drop. A role whose grant changes between
 * `public` grants is regranted in place; one that becomes, stops being or
 * changes the schema it owns is dropped (its schema handed back) and created
 * again, so a login never holds both kinds.
 */
export function diffManagedDbRoles<TProvisioned extends ManagedDbProvisionedRole>(
  desired: ManagedDbRoleDeclaration[],
  provisioned: TProvisioned[],
): ManagedDbRoleDiff<TProvisioned> {
  const provisionedByName = new Map(provisioned.map((role) => [role.name, role]));
  const desiredByName = new Map(desired.map((role) => [role.name, role]));

  const create: ManagedDbRoleDeclaration[] = [];
  const regrant: ManagedDbRoleDeclaration[] = [];
  const replaced = new Set<string>();
  for (const role of desired) {
    const existing = provisionedByName.get(role.name);
    if (!existing) {
      create.push(role);
    } else if (grantKey(existing) !== grantKey(role)) {
      if (isManagedDbRoleGrants(role.grants) && isManagedDbRoleGrants(existing.grants)) {
        regrant.push(role);
      } else {
        replaced.add(role.name);
        create.push(role);
      }
    }
  }

  const drop = provisioned.filter((role) => !desiredByName.has(role.name) || replaced.has(role.name));
  return { create, regrant, drop };
}

export function hasManagedDbRoleChanges(diff: ManagedDbRoleDiff<ManagedDbProvisionedRole>): boolean {
  return diff.create.length > 0 || diff.regrant.length > 0 || diff.drop.length > 0;
}

// ---------------------------------------------------------------------------
// SQL builders
// ---------------------------------------------------------------------------

export interface ManagedDbRoleSqlTarget {
  /** Tenant database name. */
  dbName: string;
  /** Tenant owner login (managed_db_tenants.db_user). */
  ownerUser: string;
  /** Login role being granted/revoked. */
  roleUser: string;
}

export interface ManagedDbRoleSql {
  /** Statements to run on the instance admin connection (any database). */
  instance: string[];
  /** Statements to run while connected to the tenant database. */
  tenant: string[];
}

const TENANT_SCHEMA = 'public';

function privilegesFor(grants: ManagedDbRoleGrants): { tables: string; sequences: string } {
  return grants === 'readwrite'
    ? { tables: 'SELECT, INSERT, UPDATE, DELETE', sequences: 'SELECT, USAGE' }
    : { tables: 'SELECT', sequences: 'SELECT' };
}

/**
 * Grants for a declared role: CONNECT on the database, USAGE on `public`,
 * privileges on every existing table/sequence, and matching default
 * privileges so objects the owner creates later are covered too.
 *
 * Passwords are never part of the output; role creation stays with the caller.
 */
export function buildManagedDbRoleGrantSql(
  target: ManagedDbRoleSqlTarget & { grants: ManagedDbRoleGrants },
): ManagedDbRoleSql {
  const db = quotePostgresIdentifier(target.dbName);
  const owner = quotePostgresIdentifier(target.ownerUser);
  const role = quotePostgresIdentifier(target.roleUser);
  const schema = quotePostgresIdentifier(TENANT_SCHEMA);
  const { tables, sequences } = privilegesFor(target.grants);

  return {
    instance: [
      `GRANT CONNECT ON DATABASE ${db} TO ${role}`,
    ],
    tenant: [
      `GRANT USAGE ON SCHEMA ${schema} TO ${role}`,
      `GRANT ${tables} ON ALL TABLES IN SCHEMA ${schema} TO ${role}`,
      `GRANT ${sequences} ON ALL SEQUENCES IN SCHEMA ${schema} TO ${role}`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} GRANT ${tables} ON TABLES TO ${role}`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} GRANT ${sequences} ON SEQUENCES TO ${role}`,
    ],
  };
}

/**
 * Inverse of {@link buildManagedDbRoleGrantSql}: strip every privilege the
 * role holds in the tenant database (default privileges first so nothing is
 * re-granted mid-flight), then its database-level CONNECT. After these run
 * the role owns nothing and can be dropped.
 */
export function buildManagedDbRoleRevokeSql(target: ManagedDbRoleSqlTarget): ManagedDbRoleSql {
  const db = quotePostgresIdentifier(target.dbName);
  const owner = quotePostgresIdentifier(target.ownerUser);
  const role = quotePostgresIdentifier(target.roleUser);
  const schema = quotePostgresIdentifier(TENANT_SCHEMA);

  return {
    tenant: [
      `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE ALL ON TABLES FROM ${role}`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE ${owner} IN SCHEMA ${schema} REVOKE ALL ON SEQUENCES FROM ${role}`,
      `REVOKE ALL ON ALL TABLES IN SCHEMA ${schema} FROM ${role}`,
      `REVOKE ALL ON ALL SEQUENCES IN SCHEMA ${schema} FROM ${role}`,
      `REVOKE ALL ON SCHEMA ${schema} FROM ${role}`,
    ],
    instance: [
      `REVOKE ALL ON DATABASE ${db} FROM ${role}`,
    ],
  };
}

/**
 * Statements for a role that owns one schema. `instance`: CONNECT on the
 * database, and the platform login's membership of the role, which it needs
 * to give the role a schema and take it back (as for the owner role).
 * `create` makes the schema with the role as owner; `handOver` moves an
 * existing schema to it (its objects are moved one by one after it).
 * `snapshotRead` follows either: snapshots run as the tenant owner, so it
 * may read the schema, its tables and sequences, and those the role creates
 * later. Removal runs `handBack` (the schema to the tenant owner) and then
 * `release`: everything else the role owns in the database goes to the
 * tenant owner and what it was granted there is revoked, so the login can
 * be dropped (`DROP OWNED` also removes the role's default privileges,
 * `snapshotRead`'s among them). The schema moves first so its objects land
 * in a schema the owner may create in, which a platform login that is not a
 * superuser needs. Before either, in the same transaction, the role's
 * SECURITY DEFINER routines become SECURITY INVOKER and what others hold on
 * what it hands back is revoked; those statements depend on the catalog, so
 * the hand-back in `@eve/db` builds them.
 */
export function buildManagedDbSchemaOwnerSql(
  target: ManagedDbRoleSqlTarget & { schema: string },
): {
  instance: string[];
  create: string;
  handOver: string;
  snapshotRead: string[];
  handBack: string;
  release: string[];
} {
  const db = quotePostgresIdentifier(target.dbName);
  const owner = quotePostgresIdentifier(target.ownerUser);
  const role = quotePostgresIdentifier(target.roleUser);
  const schema = quotePostgresIdentifier(target.schema);
  return {
    instance: [
      `GRANT CONNECT ON DATABASE ${db} TO ${role}`,
      `GRANT ${role} TO CURRENT_USER`,
    ],
    create: `CREATE SCHEMA ${schema} AUTHORIZATION ${role}`,
    handOver: `ALTER SCHEMA ${schema} OWNER TO ${role}`,
    snapshotRead: [
      `GRANT USAGE ON SCHEMA ${schema} TO ${owner}`,
      `GRANT SELECT ON ALL TABLES IN SCHEMA ${schema} TO ${owner}`,
      `GRANT SELECT ON ALL SEQUENCES IN SCHEMA ${schema} TO ${owner}`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE ${role} IN SCHEMA ${schema} GRANT SELECT ON TABLES TO ${owner}`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE ${role} IN SCHEMA ${schema} GRANT SELECT ON SEQUENCES TO ${owner}`,
    ],
    handBack: `ALTER SCHEMA ${schema} OWNER TO ${owner}`,
    release: [
      `REASSIGN OWNED BY ${role} TO ${owner}`,
      `DROP OWNED BY ${role}`,
    ],
  };
}
