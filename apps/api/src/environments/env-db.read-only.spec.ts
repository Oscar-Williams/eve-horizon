import { afterAll, describe, expect, it, vi } from 'vitest';
import type { Db } from '@eve/db';
import { EnvDbService } from './env-db.service';
import type { SecretsService } from '../secrets/secrets.service';

/**
 * RT-23: read-only SQL (`eve db sql` without --write) runs in a transaction
 * set READ ONLY. A statement list that ends that transaction must not then
 * run a write outside it. This needs a real Postgres: set TEST_DATABASE_URL
 * (any database the login may create temporary tables in; nothing is kept).
 */

const testDbUrl = process.env.TEST_DATABASE_URL;

const opened: Db[] = [];

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    // Every client the service opens is a real one to the test database.
    createDbFromTarget: () => {
      const client = actual.createDbFromTarget(actual.describeConnectionTarget(testDbUrl!));
      opened.push(client);
      return client;
    },
  };
});

function service(): EnvDbService {
  const svc = new EnvDbService({} as never, {} as SecretsService);
  // The target is the test database, as an external database would be.
  Object.assign(svc, {
    resolveEnvDb: async () => ({ config: { target: { url: testDbUrl }, onPlatformServer: false }, orgId: 'org_acme' }),
    enrichContext: async (context: unknown) => context,
  });
  return svc;
}

const readOnly = (sql: string, params?: unknown[]) =>
  service().executeSql('proj_shop', 'dev', sql, params, false, {} as never);

afterAll(async () => {
  await Promise.all(opened.map((client) => client.end({ timeout: 1 }).catch(() => {})));
});

describe.skipIf(!testDbUrl)('read-only SQL (RT-23)', () => {
  it('runs a read', async () => {
    await expect(readOnly('SELECT 1 AS one')).resolves.toMatchObject({ rows: [{ one: 1 }] });
  });

  it('refuses a write', async () => {
    await expect(readOnly('CREATE TEMP TABLE rt23_direct (id int)')).rejects.toThrow();
  });

  it('refuses a statement list that commits the read-only transaction and then writes', async () => {
    await expect(readOnly('COMMIT; CREATE TEMP TABLE rt23_escape (id int)')).rejects.toThrow();
  });

  it('refuses a statement list that starts a new transaction', async () => {
    await expect(readOnly('ROLLBACK; BEGIN; CREATE TEMP TABLE rt23_begin (id int)')).rejects.toThrow();
  });

  it('still runs a parameterised read', async () => {
    await expect(readOnly('SELECT $1::int AS n', [7])).resolves.toMatchObject({ rows: [{ n: 7 }] });
  });
});
