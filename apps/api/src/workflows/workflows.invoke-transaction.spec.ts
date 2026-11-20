import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { createDb, type Db } from '@eve/db';
import { WorkflowsService } from './workflows.service.js';

/**
 * R8-02 against a real Postgres: no other connection sees a workflow run's
 * root before its steps. A hook pauses the invoke right after the root is
 * inserted; a second connection reading the root by id then finds nothing,
 * and finds the whole run once the invoke finishes. Set TEST_DATABASE_URL to
 * a migrated database; the rows are removed afterwards.
 */

const testDbUrl = process.env.TEST_DATABASE_URL;

const hook = vi.hoisted(() => ({
  afterRootInsert: null as null | ((rootId: string) => Promise<void>),
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    // Every job query set is the real one, with a pause after a root insert.
    jobQueries: (db: Db) => {
      const queries = actual.jobQueries(db);
      return {
        ...queries,
        async create(row: Parameters<typeof queries.create>[0]) {
          const job = await queries.create(row);
          if (row.parent_id === null && hook.afterRootInsert) {
            await hook.afterRootInsert(row.id);
          }
          return job;
        },
      };
    },
  };
});

const suffix = Math.random().toString(36).slice(2, 6);
const org = `org_acme${suffix}`;
const project = `proj_shop${suffix}`;
const slug = `shop${suffix}`;

const MANIFEST = `
name: shop
workflows:
  restock:
    steps:
      - name: count
        script:
          run: "true"
      - name: order
        depends_on: [count]
        script:
          run: "true"
`;

describe.skipIf(!testDbUrl)('workflow invoke against a real database (R8-02)', () => {
  let db: Db;
  let other: Db;

  beforeAll(async () => {
    db = createDb(testDbUrl!);
    other = createDb(testDbUrl!);
    await db`INSERT INTO orgs (id, name, slug) VALUES (${org}, ${org}, ${`acme${suffix}`})`;
    await db`
      INSERT INTO projects (id, org_id, name, slug, repo_url)
      VALUES (${project}, ${org}, ${project}, ${slug}, 'https://eve.example/shop.git')
    `;
    await db`
      INSERT INTO project_manifests (id, project_id, manifest_yaml, manifest_hash)
      VALUES (${`manifest_${suffix}`}, ${project}, ${MANIFEST}, ${`hash${suffix}`})
    `;
  });

  afterAll(async () => {
    hook.afterRootInsert = null;
    if (db) {
      await db`DELETE FROM jobs WHERE project_id = ${project}`;
      await db`DELETE FROM projects WHERE id = ${project}`;
      await db`DELETE FROM orgs WHERE id = ${org}`;
      await db.end({ timeout: 1 });
    }
    if (other) await other.end({ timeout: 1 });
  });

  it('shows another connection no root until the whole run is written', async () => {
    const service = new WorkflowsService(db, { can: async () => ({ allowed: true }) } as never);
    let seenWhilePaused: unknown[] | null = null;
    let rootId = '';
    hook.afterRootInsert = async (id) => {
      rootId = id;
      seenWhilePaused = [...(await other`SELECT id FROM jobs WHERE id = ${id}`)];
    };

    const result = await service.invoke(project, 'restock', { input: {} });

    expect(rootId).not.toBe('');
    expect(seenWhilePaused).toEqual([]);
    expect(result).toMatchObject({ job_id: rootId });
    const rows = await other<Array<{ id: string; phase: string; step_name: string | null }>>`
      SELECT id, phase, step_name FROM jobs WHERE id = ${rootId} OR parent_id = ${rootId} ORDER BY id
    `;
    expect(rows.map((row) => [row.step_name ?? 'root', row.phase])).toEqual([
      ['root', 'active'],
      ['count', 'ready'],
      ['order', 'ready'],
    ]);
  });
});
