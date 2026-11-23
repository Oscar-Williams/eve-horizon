/**
 * Schema-owner roles inside a tenant database (EVE-071). A declared managed
 * DB role may own one named schema: DDL there, and no grants of its own in
 * `public` (it keeps what PUBLIC holds there, as every role does). These
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

/**
 * Every transaction here resolves names in pg_catalog only, whatever the
 * session's search path: catalog names are also written in full, and
 * tenant objects are always named with their schema. Operators resolve
 * through the search path, so this is what keeps a tenant-made `=` out.
 */
const CATALOG_SEARCH_PATH = 'SET LOCAL search_path = pg_catalog';

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

/**
 * The owner of a schema of the connected database, or null when there is no
 * such schema. Catalog names are written in full; the helpers below also
 * pin the search path to pg_catalog around it.
 */
export async function managedDbSchemaOwner(tenantSql: Db, schema: string): Promise<string | null> {
  const [row] = await tenantSql<{ owner: string }[]>`
    SELECT pg_catalog.pg_get_userbyid(nspowner) AS owner FROM pg_catalog.pg_namespace WHERE nspname = ${schema}
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
           pg_catalog.format('%I.%I', n.nspname, c.relname) AS identity,
           pg_catalog.pg_get_userbyid(c.relowner) AS owner
    FROM pg_catalog.pg_class c
    JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname = ${schema}
      AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f', 'c')
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_depend d
        WHERE d.classid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.objid = c.oid
          AND (d.deptype = 'e' OR (c.relkind = 'S' AND d.refclassid = 'pg_catalog.pg_class'::pg_catalog.regclass AND d.deptype IN ('a', 'i')))
      )
    UNION ALL
    SELECT 'routine',
           pg_catalog.format('%I.%I(%s)', n.nspname, p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid)),
           pg_catalog.pg_get_userbyid(p.proowner)
    FROM pg_catalog.pg_proc p
    JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
    WHERE n.nspname = ${schema}
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_depend d
        WHERE d.classid = 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid = p.oid AND d.deptype = 'e'
      )
    UNION ALL
    SELECT CASE t.typtype WHEN 'd' THEN 'domain' ELSE 'type' END,
           pg_catalog.format('%I.%I', n.nspname, t.typname),
           pg_catalog.pg_get_userbyid(t.typowner)
    FROM pg_catalog.pg_type t
    JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
    WHERE n.nspname = ${schema}
      AND t.typtype IN ('b', 'd', 'e', 'r')
      AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type e WHERE e.typarray = t.oid)
      AND NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_depend d
        WHERE d.classid = 'pg_catalog.pg_type'::pg_catalog.regclass AND d.objid = t.oid AND d.deptype = 'e'
      )
    ORDER BY 1, 2
  `;
}

/**
 * The objects of a schema a hand-over does not move, one row each, as
 * "<kind> <identity>": operators, operator classes and families, collations,
 * conversions, statistics objects, text-search configurations and
 * dictionaries, and ordered-set aggregates (ALTER ROUTINE cannot name one).
 * Extension members follow their extension; text-search parsers and
 * templates have no owner, so they need no move.
 */
async function unmovableObjects(tx: Db, schema: string): Promise<string[]> {
  const rows = await tx<{ object: string }[]>`
    WITH ns AS (
      SELECT oid FROM pg_catalog.pg_namespace WHERE nspname = ${schema}
    ), found (kind, classid, objid) AS (
      SELECT 'operator', 'pg_catalog.pg_operator'::pg_catalog.regclass, o.oid
      FROM pg_catalog.pg_operator o WHERE o.oprnamespace = (SELECT oid FROM ns)
      UNION ALL
      SELECT 'operator class', 'pg_catalog.pg_opclass'::pg_catalog.regclass, c.oid
      FROM pg_catalog.pg_opclass c WHERE c.opcnamespace = (SELECT oid FROM ns)
      UNION ALL
      SELECT 'operator family', 'pg_catalog.pg_opfamily'::pg_catalog.regclass, f.oid
      FROM pg_catalog.pg_opfamily f WHERE f.opfnamespace = (SELECT oid FROM ns)
      UNION ALL
      SELECT 'collation', 'pg_catalog.pg_collation'::pg_catalog.regclass, l.oid
      FROM pg_catalog.pg_collation l WHERE l.collnamespace = (SELECT oid FROM ns)
      UNION ALL
      SELECT 'conversion', 'pg_catalog.pg_conversion'::pg_catalog.regclass, v.oid
      FROM pg_catalog.pg_conversion v WHERE v.connamespace = (SELECT oid FROM ns)
      UNION ALL
      SELECT 'statistics object', 'pg_catalog.pg_statistic_ext'::pg_catalog.regclass, s.oid
      FROM pg_catalog.pg_statistic_ext s WHERE s.stxnamespace = (SELECT oid FROM ns)
      UNION ALL
      SELECT 'text search configuration', 'pg_catalog.pg_ts_config'::pg_catalog.regclass, g.oid
      FROM pg_catalog.pg_ts_config g WHERE g.cfgnamespace = (SELECT oid FROM ns)
      UNION ALL
      SELECT 'text search dictionary', 'pg_catalog.pg_ts_dict'::pg_catalog.regclass, t.oid
      FROM pg_catalog.pg_ts_dict t WHERE t.dictnamespace = (SELECT oid FROM ns)
      UNION ALL
      SELECT 'ordered-set aggregate', 'pg_catalog.pg_proc'::pg_catalog.regclass, p.oid
      FROM pg_catalog.pg_proc p
      JOIN pg_catalog.pg_aggregate a ON a.aggfnoid = p.oid
      WHERE p.pronamespace = (SELECT oid FROM ns) AND a.aggkind <> 'n'
    )
    SELECT pg_catalog.concat_ws(' ', found.kind, (pg_catalog.pg_identify_object(found.classid, found.objid, 0)).identity) AS object
    FROM found
    WHERE NOT EXISTS (
      SELECT 1 FROM pg_catalog.pg_depend d
      WHERE d.classid = found.classid AND d.objid = found.objid AND d.deptype = 'e'
    )
    ORDER BY 1
  `;
  return rows.map((row) => row.object);
}

/** At most this many unmovable objects are named in a refusal. */
const UNMOVABLE_LISTED = 5;

/**
 * Why the role cannot be given its schema now, as a ManagedDbSchemaConflictError,
 * or nothing: the schema is new, the role's, or the tenant owner's with every
 * object in it the owner's (or the role's) and of a kind a hand-over moves.
 * Owners in `releasing` count as the tenant owner: their schema is handed
 * back before the claim.
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
  if (foreign.length > 0) {
    return {
      owner,
      objects,
      conflict: new ManagedDbSchemaConflictError(
        `Schema "${target.schema}" holds objects owned by ${foreign.map((name) => `"${name}"`).join(', ')}, ` +
        'not by the tenant owner; nothing was handed over',
      ),
    };
  }
  const unmovable = await unmovableObjects(tx, target.schema);
  if (unmovable.length === 0) return { owner, objects, conflict: null };
  const more = unmovable.length - UNMOVABLE_LISTED;
  const listed = unmovable.slice(0, UNMOVABLE_LISTED).join(', ') + (more > 0 ? `, and ${more} more` : '');
  return {
    owner,
    objects,
    conflict: new ManagedDbSchemaConflictError(
      `Schema "${target.schema}" holds objects a hand-over does not move: ${listed}; ` +
      'nothing was handed over: move them to another schema or drop them, then deploy again',
    ),
  };
}

/**
 * Check, changing nothing, that the role can be given its schema: throws
 * ManagedDbSchemaConflictError when another role holds the schema or an
 * object in it, or it holds an object a hand-over does not move. Owners in `releasing` (roles whose schema this run hands back
 * first) count as the tenant owner.
 */
export async function checkManagedDbSchemaClaim(
  tenantSql: Db,
  target: ManagedDbSchemaTarget,
  options: { releasing?: readonly string[] } = {},
): Promise<void> {
  await tenantSql.begin(async (rawTx) => {
    const tx = rawTx as unknown as Db;
    await tx.unsafe(CATALOG_SEARCH_PATH);
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
 * - owned by any other role, holding an object another role owns, or
 *   holding an object of a kind a hand-over does not move (an operator, say):
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
    await tx.unsafe(CATALOG_SEARCH_PATH);

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
 * The SECURITY DEFINER functions and procedures the role owns anywhere in the
 * connected database, by identity: handed back, they would run with the
 * tenant owner's rights.
 */
async function definerRoutines(tx: Db, roleUser: string): Promise<string[]> {
  const rows = await tx<{ identity: string }[]>`
    SELECT (pg_catalog.pg_identify_object('pg_catalog.pg_proc'::pg_catalog.regclass, p.oid, 0)).identity AS identity
    FROM pg_catalog.pg_proc p
    WHERE p.prosecdef AND p.proowner = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = ${roleUser})
    ORDER BY 1
  `;
  return rows.map((row) => row.identity);
}

/**
 * What the hand-back gives the tenant owner that anyone else holds a
 * privilege on: the schema, while the role owns it, and every table, view,
 * sequence, routine and type the role owns anywhere in the database (column
 * privileges count for their table). One row per object, with its REVOKE
 * keyword, its identity, and every grantee but the role and the tenant owner,
 * PUBLIC included (functions and types grant it EXECUTE and USAGE until that
 * is revoked), as a list for REVOKE.
 */
async function handedBackGrants(
  tx: Db,
  target: ManagedDbSchemaTarget,
): Promise<Array<{ keyword: string; identity: string; grantees: string }>> {
  return tx<Array<{ keyword: string; identity: string; grantees: string }>>`
    WITH departing AS (
      SELECT oid FROM pg_catalog.pg_roles WHERE rolname = ${target.roleUser}
    ), tenant_owner AS (
      SELECT oid FROM pg_catalog.pg_roles WHERE rolname = ${target.ownerUser}
    ), handed (keyword, classid, objid, acl) AS (
      SELECT 'SCHEMA', 'pg_catalog.pg_namespace'::pg_catalog.regclass, n.oid, n.nspacl
      FROM pg_catalog.pg_namespace n
      WHERE n.nspname = ${target.schema} AND n.nspowner = (SELECT oid FROM departing)
      UNION ALL
      SELECT CASE c.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END,
             'pg_catalog.pg_class'::pg_catalog.regclass, c.oid, c.relacl
      FROM pg_catalog.pg_class c
      WHERE c.relowner = (SELECT oid FROM departing) AND c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
      UNION ALL
      SELECT 'TABLE', 'pg_catalog.pg_class'::pg_catalog.regclass, c.oid, a.attacl
      FROM pg_catalog.pg_attribute a
      JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
      WHERE c.relowner = (SELECT oid FROM departing) AND a.attacl IS NOT NULL
      UNION ALL
      SELECT 'ROUTINE', 'pg_catalog.pg_proc'::pg_catalog.regclass, p.oid,
             COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
      FROM pg_catalog.pg_proc p
      WHERE p.proowner = (SELECT oid FROM departing)
      UNION ALL
      SELECT 'TYPE', 'pg_catalog.pg_type'::pg_catalog.regclass, t.oid,
             COALESCE(t.typacl, pg_catalog.acldefault('T', t.typowner))
      FROM pg_catalog.pg_type t
      WHERE t.typowner = (SELECT oid FROM departing)
        AND t.typtype IN ('b', 'c', 'd', 'e', 'r')
        AND (t.typrelid = 0 OR (SELECT c.relkind FROM pg_catalog.pg_class c WHERE c.oid = t.typrelid) = 'c')
        AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_type e WHERE e.typarray = t.oid)
    ), grants AS (
      SELECT DISTINCT h.keyword, h.classid, h.objid,
             CASE WHEN a.grantee = 0 THEN 'PUBLIC'
                  ELSE pg_catalog.quote_ident(pg_catalog.pg_get_userbyid(a.grantee)) END AS grantee
      FROM handed h
      CROSS JOIN LATERAL pg_catalog.aclexplode(h.acl) a
      WHERE a.grantee <> (SELECT oid FROM departing) AND a.grantee <> (SELECT oid FROM tenant_owner)
    )
    SELECT g.keyword,
           (pg_catalog.pg_identify_object(g.classid, g.objid, 0)).identity AS identity,
           pg_catalog.string_agg(g.grantee, ', ' ORDER BY g.grantee) AS grantees
    FROM grants g
    GROUP BY g.keyword, g.classid, g.objid
    ORDER BY 1, 2
  `;
}

/**
 * Hand back what the role owns in the tenant database. First the login stops
 * signing in and its sessions end, so nothing it commits meanwhile is dropped
 * by DROP OWNED or left behind to keep the login. Then, in one transaction:
 * the role's SECURITY DEFINER functions and procedures become SECURITY
 * INVOKER, and what anyone but the tenant owner holds on the schema and on
 * the role's objects is revoked (with what they passed on), so nothing handed
 * back runs or reads with the owner's rights for another login; then its
 * schema (when it still owns it) and every other object it owns go to the
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
    await tenantSql.begin(async (rawTx) => {
      const tx = rawTx as unknown as Db;
      await tx.unsafe(CATALOG_SEARCH_PATH);
      await tx`
        SELECT pg_catalog.pg_terminate_backend(pid, ${SESSION_END_WAIT_MS})
        FROM pg_catalog.pg_stat_activity
        WHERE usename = ${target.roleUser} AND pid <> pg_catalog.pg_backend_pid()
      `;
    });
    await tenantSql.begin(async (rawTx) => {
      const tx = rawTx as unknown as Db;
      await tx.unsafe(`SET LOCAL lock_timeout = '${LOCK_TIMEOUT}'`);
      await tx.unsafe(CATALOG_SEARCH_PATH);
      for (const routine of await definerRoutines(tx, target.roleUser)) {
        await tx.unsafe(`ALTER ROUTINE ${routine} SECURITY INVOKER`);
      }
      for (const { keyword, identity, grantees } of await handedBackGrants(tx, target)) {
        await tx.unsafe(`REVOKE ALL ON ${keyword} ${identity} FROM ${grantees} CASCADE`);
      }
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
