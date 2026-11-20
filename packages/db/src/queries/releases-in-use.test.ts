/**
 * A release an environment names as its current or last applied release is
 * not deleted: the worker renews that environment's service tokens against
 * it, and the API refuses to mint against a release that is gone. A direct
 * delete leaves it (the API answers 409), and pruning skips it.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import postgres from 'postgres';
import { releaseQueries } from './releases.js';
import type { Db } from '../client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 8);
const org = `org_acme${suffix}`;
const project = `proj_shop${suffix}`;
const rel = (n: number) => `rel_${n}${suffix}`;

describe('releases in use', () => {
  let db: Db;

  beforeAll(async () => {
    db = postgres(testDbUrl!, { max: 2 }) as unknown as Db;
    await db`INSERT INTO orgs (id, name, slug) VALUES (${org}, ${org}, ${`a${suffix}`})`;
    await db`INSERT INTO projects (id, org_id, name, slug, repo_url)
             VALUES (${project}, ${org}, ${project}, ${`s${suffix}`}, 'https://example.com/shop.git')`;
    for (const n of [1, 2, 3, 4, 5]) {
      await db`INSERT INTO releases (id, project_id, git_sha, manifest_hash, created_at)
               VALUES (${rel(n)}, ${project}, ${`sha${n}`}, ${`hash-${n}`}, NOW() - ${`${10 - n} minutes`}::interval)`;
    }
    // prod runs release 1 (current and applied); staging's current is 2, its last apply 3.
    await db`INSERT INTO environments (id, project_id, name, type, current_release_id, last_applied_release_id)
             VALUES (${`env_prod${suffix}`}, ${project}, 'prod', 'persistent', ${rel(1)}, ${rel(1)}),
                    (${`env_stage${suffix}`}, ${project}, 'staging', 'persistent', ${rel(2)}, ${rel(3)})`;
  });

  afterAll(async () => {
    await db`DELETE FROM environments WHERE project_id = ${project}`;
    await db`DELETE FROM releases WHERE project_id = ${project}`;
    await db`DELETE FROM projects WHERE id = ${project}`;
    await db`DELETE FROM orgs WHERE id = ${org}`;
    await (db as unknown as { end: () => Promise<void> }).end();
  });

  const exists = async (id: string) => (await releaseQueries(db).findById(id)) !== null;

  it('names the environments that use a release', async () => {
    const releases = releaseQueries(db);
    expect(await releases.listEnvironmentsUsing(rel(1))).toEqual(['prod']);
    expect(await releases.listEnvironmentsUsing(rel(3))).toEqual(['staging']);
    expect(await releases.listEnvironmentsUsing(rel(4))).toEqual([]);
  });

  it('does not delete a release an environment names as current or last applied', async () => {
    const releases = releaseQueries(db);

    expect(await releases.delete(rel(2))).toBe(false);
    expect(await releases.delete(rel(3))).toBe(false);
    expect(await exists(rel(2))).toBe(true);
    expect(await exists(rel(3))).toBe(true);
  });

  it('prunes past the newest only the releases no environment uses', async () => {
    const deleted = await releaseQueries(db).deleteByProjectOlderThan(project, 1);

    // Release 4 only: 5 is the newest, kept; 1 to 3 are in use.
    expect(deleted).toBe(1);
    expect(await exists(rel(5))).toBe(true);
    expect(await exists(rel(4))).toBe(false);
    for (const n of [1, 2, 3]) expect(await exists(rel(n))).toBe(true);
  });

  it('deletes a release once no environment uses it', async () => {
    await db`UPDATE environments SET last_applied_release_id = ${rel(2)} WHERE id = ${`env_stage${suffix}`}`;

    expect(await releaseQueries(db).delete(rel(3))).toBe(true);
    expect(await exists(rel(3))).toBe(false);
  });
});
