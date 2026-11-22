/**
 * Schema-owner roles inside a tenant database (EVE-071). A declared managed
 * DB role may own one named schema: DDL there, nothing in `public`. These
 * helpers run on a connection to the tenant database as the platform login,
 * which must be a member of the tenant owner and of the role (the reconciler
 * grants both). They need no superuser: on Cloud SQL the platform login is
 * not one.
 */

import { buildManagedDbSchemaOwnerSql, quotePostgresIdentifier } from '@eve/shared';
import type { Db } from './client.js';

export interface ManagedDbSchemaTarget {
  /** Tenant database name. */
  dbName: string;
  /** The schema the role owns. */
  schema: string;
  /** The schema-owner login. */
  roleUser: string;
  /** The tenant owner login (owner of the database). */
  ownerUser: string;
}

/** What a claim did: made the schema, found it already the role's, or moved it from the tenant owner. */
export type ManagedDbSchemaClaim =
  | { action: 'created' }
  | { action: 'unchanged' }
  | { action: 'handed_over'; objects: Record<string, number> };

/** The schema, or an object in it, belongs to a role that is neither the tenant owner nor the schema's role. */
export class ManagedDbSchemaConflictError extends Error {
  readonly code = 'schema_owner_conflict';
}

/** How long a hand-over waits for a lock (each object change takes an exclusive one) before it fails. */
const LOCK_TIMEOUT = '5s';

/** How long a hand-back waits for each session of the role to end (Postgres 14 and later). */
const SESSION_END_WAIT_MS = 5000;

/** The object kinds a hand-over moves, and the ALTER keyword for each. */
const OBJECT_KEYWORDS: Record<string, string> = {
  table: 'TABLE',
  view: 'VIEW',
  materialized_view: 'MATERIALIZED VIEW',
  sequence: 'SEQUENCE',
  foreign_table: 'FOREIGN TABLE',
  type: 'TYPE',
  domain: 'DOMAIN',
  routine: 'ROUTINE',
};

interface SchemaObject {
  kind: string;
  identity: string;
  owner: string;
}

/** The owner of a schema of the connected database, or null when there is no such schema. */
export async function managedDbSchemaOwner(tenantSql: Db, schema: string): Promise<string | null> {
  const [row] = await tenantSql<{ owner: string }[]>`
    SELECT pg_get_userbyid(nspowner) AS owner FROM pg_namespace WHERE nspname = ${schema}
  `;
  return row?.owner ?? null;
}

/**
 * The objects of a schema that change owner one by one: tables (with their
 * indexes and owned sequences), views, materialised views, sequences no
 * column owns, foreign tables, composite, enum, range and base types,
 * domains, and functions, procedures and aggregates. Array types follow
 * their element, multiranges their range, and extension members their
 * extension. Identities are schema-qualified and quoted.
 */
async function schemaObjects(tx: Db, schema: string): Promise<SchemaObject[]> {
  return tx<SchemaObject[]>`
    SELECT CASE c.relkind
             WHEN 'r' THEN 'table' WHEN 'p' THEN 'table'
             WHEN 'v' THEN 'view' WHEN 'm' THEN 'materialized_view'
             WHEN 'S' THEN 'sequence' WHEN 'f' THEN 'foreign_table'
             ELSE 'type'
           END AS kind,
           format('%I.%I', n.nspname, c.relname) AS identity,
           pg_get_userbyid(c.relowner) AS owner
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = ${schema}
      AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c')
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend d
        WHERE d.classid = 'pg_class'::regclass AND d.objid = c.oid
          AND (d.deptype = 'e' OR (c.relkind = 'S' AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')))
      )
    UNION ALL
    SELECT 'routine',
           format('%I.%I(%s)', n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)),
           pg_get_userbyid(p.proowner)
    FROM pg_proc p
    JOIN pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = ${schema}
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend d
        WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid AND d.deptype = 'e'
      )
    UNION ALL
    SELECT CASE t.typtype WHEN 'd' THEN 'domain' ELSE 'type' END,
           format('%I.%I', n.nspname, t.typname),
           pg_get_userbyid(t.typowner)
    FROM pg_type t
    JOIN pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = ${schema}
      AND t.typtype IN ('b', 'd', 'e', 'r')
      AND NOT EXISTS (SELECT 1 FROM pg_type e WHERE e.typarray = t.oid)
      AND NOT EXISTS (
        SELECT 1 FROM pg_depend d
        WHERE d.classid = 'pg_type'::regclass AND d.objid = t.oid AND d.deptype = 'e'
      )
    ORDER BY 1, 2
  `;
}

/**
 * Why the role cannot be given its schema now, as a ManagedDbSchemaConflictError,
 * or nothing: the schema is new, the role's, or the tenant owner's with every
 * object in it the owner's (or the role's). Owners in `releasing` count as
 * the tenant owner: their schema is handed back before the claim.
 */
async function claimProblem(
  tx: Db,
  target: ManagedDbSchemaTarget,
  releasing: readonly string[] = [],
): Promise<{ owner: string | null; objects: SchemaObject[]; conflict: ManagedDbSchemaConflictError | null }> {
  const asOwner = (name: string) => (releasing.includes(name) ? target.ownerUser : name);
  const found = await managedDbSchemaOwner(tx, target.schema);
  const owner = found === null ? null : asOwner(found);
  if (owner === null || owner === target.roleUser) return { owner, objects: [], conflict: null };
  if (owner !== target.ownerUser) {
    return {
      owner,
      objects: [],
      conflict: new ManagedDbSchemaConflictError(
        `Schema "${target.schema}" is owned by "${owner}", not by the tenant owner; ` +
        'a role is given only a schema that is new or that the tenant owner owns',
      ),
    };
  }
  const objects = await schemaObjects(tx, target.schema);
  const foreign = [...new Set(
    objects.map((object) => asOwner(object.owner))
      .filter((name) => name !== target.ownerUser && name !== target.roleUser),
  )];
  if (foreign.length === 0) return { owner, objects, conflict: null };
  return {
    owner,
    objects,
    conflict: new ManagedDbSchemaConflictError(
      `Schema "${target.schema}" holds objects owned by ${foreign.map((name) => `"${name}"`).join(', ')}, ` +
      'not by the tenant owner; nothing was handed over',
    ),
  };
}

/**
 * Check, changing nothing, that the role can be given its schema: throws
 * ManagedDbSchemaConflictError when another role holds the schema or an
 * object in it. Owners in `releasing` (roles whose schema this run hands back
 * first) count as the tenant owner.
 */
export async function checkManagedDbSchemaClaim(
  tenantSql: Db,
  target: ManagedDbSchemaTarget,
  options: { releasing?: readonly string[] } = {},
): Promise<void> {
  await tenantSql.begin(async (rawTx) => {
    const tx = rawTx as unknown as Db;
    await tx.unsafe('SET LOCAL search_path = pg_catalog');
    const { conflict } = await claimProblem(tx, target, options.releasing);
    if (conflict) throw conflict;
  });
}

/**
 * Give the role its schema, in one transaction:
 * - no such schema: create it, owned by the role;
 * - owned by the role: nothing;
 * - owned by the tenant owner: hand over the schema, then each object in it
 *   the owner owns, and take back what PUBLIC and `revokeFrom` (the tenant's
 *   other logins) were granted on the schema;
 * - owned by any other role, or holding an object another role owns:
 *   refused with ManagedDbSchemaConflictError, and nothing changes.
 * A created or handed-over schema stays readable by the tenant owner, which
 * snapshots run as: the schema, its tables and sequences, and those the role
 * creates later.
 */
export async function claimManagedDbSchema(
  tenantSql: Db,
  target: ManagedDbSchemaTarget,
  options: { revokeFrom?: string[] } = {},
): Promise<ManagedDbSchemaClaim> {
  const sql = buildManagedDbSchemaOwnerSql(target);
  const role = quotePostgresIdentifier(target.roleUser);
  return tenantSql.begin(async (rawTx) => {
    const tx = rawTx as unknown as Db;
    await tx.unsafe(`SET LOCAL lock_timeout = '${LOCK_TIMEOUT}'`);
    // Catalog names come out schema-qualified whatever the login's path.
    await tx.unsafe('SET LOCAL search_path = pg_catalog');

    const { owner, objects, conflict } = await claimProblem(tx, target);
    if (conflict) throw conflict;
    if (owner === null) {
      await tx.unsafe(sql.create);
      for (const statement of sql.snapshotRead) await tx.unsafe(statement);
      return { action: 'created' } as const;
    }
    if (owner === target.roleUser) return { action: 'unchanged' } as const;

    await tx.unsafe(sql.handOver);
    const counts: Record<string, number> = {};
    for (const object of objects) {
      if (object.owner !== target.ownerUser) continue;
      await tx.unsafe(`ALTER ${OBJECT_KEYWORDS[object.kind]} ${object.identity} OWNER TO ${role}`);
      counts[object.kind] = (counts[object.kind] ?? 0) + 1;
    }
    const grantees = ['PUBLIC', ...(options.revokeFrom ?? [])
      .filter((name) => name !== target.roleUser)
      .map(quotePostgresIdentifier)];
    await tx.unsafe(`REVOKE ALL ON SCHEMA ${quotePostgresIdentifier(target.schema)} FROM ${grantees.join(', ')}`);
    for (const statement of sql.snapshotRead) await tx.unsafe(statement);
    return { action: 'handed_over', objects: counts } as const;
  }) as Promise<ManagedDbSchemaClaim>;
}

/**
 * Hand back what the role owns in the tenant database. First the login stops
 * signing in and its sessions end, so nothing it commits meanwhile is dropped
 * by DROP OWNED or left behind to keep the login. Then, in one transaction,
 * its schema (when it still owns it) and every other object it owns go to the
 * tenant owner, and the privileges it was granted there, CONNECT on the
 * database included, are revoked. The login can then be dropped. When the
 * transaction fails nothing has moved, and the login may sign in again.
 */
export async function releaseManagedDbSchema(tenantSql: Db, target: ManagedDbSchemaTarget): Promise<void> {
  const sql = buildManagedDbSchemaOwnerSql(target);
  const role = quotePostgresIdentifier(target.roleUser);
  // Committed on its own, so no session of the role starts after it.
  await tenantSql.unsafe(`ALTER ROLE ${role} NOLOGIN`);
  try {
    await tenantSql`
      SELECT pg_catalog.pg_terminate_backend(pid, ${SESSION_END_WAIT_MS})
      FROM pg_catalog.pg_stat_activity
      WHERE usename = ${target.roleUser} AND pid <> pg_catalog.pg_backend_pid()
    `;
    await tenantSql.begin(async (rawTx) => {
      const tx = rawTx as unknown as Db;
      await tx.unsafe(`SET LOCAL lock_timeout = '${LOCK_TIMEOUT}'`);
      if ((await managedDbSchemaOwner(tx, target.schema)) === target.roleUser) {
        await tx.unsafe(sql.handBack);
      }
      for (const statement of sql.release) {
        await tx.unsafe(statement);
      }
    });
  } catch (err) {
    // The error that stopped the hand-back is the one to report; should this
    // fail too, the login stays unable to sign in until the next run.
    await tenantSql.unsafe(`ALTER ROLE ${role} LOGIN`).catch(() => undefined);
    throw err;
  }
}
