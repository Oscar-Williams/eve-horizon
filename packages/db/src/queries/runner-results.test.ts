/**
 * A runner pod reports its attempt's result once. The first report is kept;
 * a second is refused, so job code holding the attempt's token cannot
 * replace the result the runner pushed. The result goes with its attempt.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import postgres from 'postgres';
import { runnerResultQueries } from './runner-results.js';
import type { Db } from '../client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 8);
const org = `org_acme${suffix}`;
const project = `proj_shop${suffix}`;
const job = `shop-${suffix}`;

describe('runner results', () => {
  let db: Db;
  let attemptId: string;

  beforeAll(async () => {
    db = postgres(testDbUrl!, { max: 2 }) as unknown as Db;
    await db`INSERT INTO orgs (id, name, slug) VALUES (${org}, ${org}, ${`a${suffix}`})`;
    await db`INSERT INTO projects (id, org_id, name, slug, repo_url)
             VALUES (${project}, ${org}, ${project}, ${`s${suffix}`}, 'https://example.com/shop.git')`;
    await db`INSERT INTO jobs (id, project_id, title, description) VALUES (${job}, ${project}, 'job', 'job')`;
    const [attempt] = await db<{ id: string }[]>`
      INSERT INTO job_attempts (job_id, attempt_number, status) VALUES (${job}, 1, 'running') RETURNING id`;
    attemptId = attempt.id;
  });

  afterAll(async () => {
    await db`DELETE FROM jobs WHERE id = ${job}`;
    await db`DELETE FROM projects WHERE id = ${project}`;
    await db`DELETE FROM orgs WHERE id = ${org}`;
    await (db as unknown as { end: () => Promise<void> }).end();
  });

  it('keeps the first result for an attempt and refuses a second', async () => {
    const results = runnerResultQueries(db);
    expect(await results.find(attemptId)).toBeNull();

    expect(await results.record(attemptId, { success: true, exit_code: 0, result_text: 'first' })).toBe(true);
    expect(await results.record(attemptId, { success: false, exit_code: 1, result_text: 'second' })).toBe(false);

    const stored = await results.find(attemptId);
    expect(stored?.result).toMatchObject({ success: true, exit_code: 0, result_text: 'first' });
    expect(stored?.received_at).toBeInstanceOf(Date);
  });

  it('removes the result with its attempt', async () => {
    await db`DELETE FROM job_attempts WHERE id = ${attemptId}::uuid`;
    expect(await runnerResultQueries(db).find(attemptId)).toBeNull();
  });
});
