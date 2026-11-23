import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { createDb, describeConnectionTarget, type Db } from '@eve/db';
import { EnvDbService } from './env-db.service';
import type { SecretsService } from '../secrets/secrets.service';

/**
 * On Eve's own database server, env-db refuses a login with superuser or
 * equivalent rights before running anything. The database's owner controls
 * the database's search_path, and the URL may set one too, so the check must
 * not resolve a catalog name, function or operator through either: here the
 * owner puts "public" first and plants a `pg_roles` view with no rows, a
 * `pg_has_role` that says no, and an `=` that says no.
 *
 * Needs a real Postgres whose login is a superuser: set TEST_DATABASE_URL.
 * The spec creates and drops its own database and roles.
 */

const testDbUrl = process.env.TEST_DATABASE_URL;

describe.skipIf(!testDbUrl)('the login privilege check on a database that shadows the catalog (real Postgres)', () => {
  const suffix = Math.random().toString(36).slice(2, 8);
  const database = `eve_guard_${suffix}`;
  const owner = `eve_guard_${suffix}_owner`;
  const reader = `eve_guard_${suffix}_reader`;
  let server: Db;

  const shadowing = [
    `ALTER DATABASE "${database}" SET search_path = public, pg_catalog`,
    'CREATE VIEW public.pg_roles AS SELECT * FROM pg_catalog.pg_roles WHERE false',
    'GRANT SELECT ON public.pg_roles TO PUBLIC',
    `CREATE FUNCTION public.pg_has_role(name, oid, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'`,
    `CREATE FUNCTION public.shadow_name_text_eq(name, text) RETURNS boolean LANGUAGE sql AS 'SELECT false'`,
    'CREATE OPERATOR public.= (LEFTARG = name, RIGHTARG = text, FUNCTION = public.shadow_name_text_eq)',
  ];

  /** A URL for `user` on the spec's database, with an optional query string. */
  function urlFor(user: string, query = ''): string {
    const url = new URL(testDbUrl!);
    url.username = user;
    url.password = '';
    url.pathname = `/${database}`;
    url.search = query;
    return url.toString();
  }

  function runSql(url: string, sql: string) {
    const service = new EnvDbService({} as never, {} as SecretsService);
    // The target is on the platform's server, so the check applies.
    Object.assign(service, {
      resolveEnvDb: async () => ({
        config: { url, schema: null, onPlatformServer: true, target: describeConnectionTarget(url) },
        orgId: 'org_acme',
      }),
      enrichContext: async (context: unknown) => context,
    });
    return service.executeSql('proj_shop', 'dev', sql, undefined, false, {} as never);
  }

  beforeAll(async () => {
    server = createDb(testDbUrl!);
    await server.unsafe(`CREATE ROLE "${owner}" NOLOGIN`);
    await server.unsafe(`CREATE ROLE "${reader}" LOGIN`);
    await server.unsafe(`CREATE DATABASE "${database}" OWNER "${owner}"`);
    const inDatabase = createDb(urlFor(new URL(testDbUrl!).username || 'postgres', 'search_path=pg_catalog'));
    try {
      await inDatabase.begin(async (tx) => {
        await tx.unsafe(`SET LOCAL ROLE "${owner}"`);
        for (const statement of shadowing) await tx.unsafe(statement);
      });
    } finally {
      await inDatabase.end({ timeout: 1 });
    }
  });

  afterAll(async () => {
    if (!server) return;
    await server`
      SELECT pg_catalog.pg_terminate_backend(pid) FROM pg_catalog.pg_stat_activity WHERE datname = ${database}
    `;
    await server.unsafe(`DROP DATABASE IF EXISTS "${database}"`);
    await server.unsafe(`DROP ROLE IF EXISTS "${reader}"`);
    await server.unsafe(`DROP ROLE IF EXISTS "${owner}"`);
    await server.end({ timeout: 1 });
  });

  it('refuses a superuser login although the database puts "public" first', async () => {
    const superuser = new URL(testDbUrl!).username;

    await expect(runSql(urlFor(superuser), 'SELECT 1 AS one')).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('refuses it when the URL itself sets that search path', async () => {
    const superuser = new URL(testDbUrl!).username;
    const url = urlFor(superuser, `search_path=${encodeURIComponent('public,pg_catalog')}`);

    await expect(runSql(url, 'SELECT 1 AS one')).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('lets an ordinary login through, whose own session keeps the database\'s search path', async () => {
    await expect(runSql(urlFor(reader), "SELECT pg_catalog.current_setting('search_path') AS search_path"))
      .resolves.toMatchObject({ rows: [{ search_path: 'public, pg_catalog' }] });
  });
});
