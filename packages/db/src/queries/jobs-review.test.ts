/**
 * A job's review is decided once, against a migrated database. An approve
 * and a reject that race must not both succeed: the second waits for the
 * first, then finds the review decided and changes nothing (no attempt is
 * created for a reject that loses). Each race holds the first decision's
 * transaction open until the second is waiting on the job's row. A decider
 * who names the attempt they reviewed decides that round only: once the job
 * is back in review on a later attempt, the decision is refused.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import postgres from 'postgres';
import { jobQueries, ReviewDecidedError, ReviewRoundChangedError } from './jobs.js';
import type { Db } from '../client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 6);
const org = `org_acme${suffix}`;
const project = `proj_shop${suffix}`;
const slug = `shop${suffix}`;
let counter = 0;

type Queries = ReturnType<typeof jobQueries>;
type Decision = (jobs: Queries, jobId: string) => Promise<unknown>;

const approveAs = (reviewer: string): Decision => (jobs, id) => jobs.approveReview(id, reviewer, 'looks right');
const rejectAs = (reviewer: string): Decision => (jobs, id) => jobs.rejectReview(id, reviewer, 'count again');

describe('review decisions', () => {
  let db: Db;
  let observer: Db;

  async function inReview(): Promise<string> {
    const id = `${slug}-${String(++counter).padStart(8, '0')}`;
    await db`
      INSERT INTO jobs (id, project_id, title, description, phase, review_required, review_status)
      VALUES (${id}, ${project}, 'restock', 'restock the shelves', 'review', 'human', 'pending')
    `;
    await db`
      INSERT INTO job_attempts (job_id, attempt_number, status, trigger_type)
      VALUES (${id}, 1, 'succeeded', 'manual')
    `;
    return id;
  }

  async function state(id: string) {
    const [job] = await observer<Array<{ phase: string; review_status: string | null; reviewer: string | null }>>`
      SELECT phase, review_status, reviewer FROM jobs WHERE id = ${id}
    `;
    const attempts = await observer<Array<{ attempt_number: number }>>`
      SELECT attempt_number FROM job_attempts WHERE job_id = ${id} ORDER BY attempt_number
    `;
    return { ...job, attempts: attempts.map((row) => row.attempt_number) };
  }

  /** Waits until some session of this database waits on a row lock. */
  async function someoneWaitsOnALock(): Promise<void> {
    for (let tries = 0; tries < 200; tries++) {
      const [row] = await observer<Array<{ waiting: number }>>`
        SELECT count(*)::int AS waiting FROM pg_stat_activity
        WHERE datname = current_database() AND wait_event_type = 'Lock'
      `;
      if (row.waiting > 0) return;
      await new Promise((resolve) => setTimeout(resolve, 25));
    }
    throw new Error('the second decision never waited on the job row');
  }

  /**
   * Makes `first` in a transaction and holds it open; starts `second` in
   * another; once `second` waits on the row, commits `first`. Returns how
   * `second` ended.
   */
  async function race(id: string, first: Decision, second: Decision): Promise<PromiseSettledResult<unknown>> {
    let commitFirst!: () => void;
    const firstMayCommit = new Promise<void>((resolve) => (commitFirst = resolve));
    let firstMade!: () => void;
    const firstIsMade = new Promise<void>((resolve) => (firstMade = resolve));

    const firstTx = db.begin(async (tx) => {
      await first(jobQueries(tx as unknown as Db), id);
      firstMade();
      await firstMayCommit;
    });
    await firstIsMade;
    const secondTx = db.begin(async (tx) => second(jobQueries(tx as unknown as Db), id));
    const [secondEnded] = await Promise.all([
      Promise.allSettled([secondTx]).then(([result]) => result),
      someoneWaitsOnALock().then(() => commitFirst()),
    ]);
    await firstTx;
    return secondEnded;
  }

  beforeAll(async () => {
    db = postgres(testDbUrl!, { max: 4 }) as unknown as Db;
    observer = postgres(testDbUrl!, { max: 1 }) as unknown as Db;
    await db`INSERT INTO orgs (id, name, slug) VALUES (${org}, ${org}, ${`acme${suffix}`})`;
    await db`
      INSERT INTO projects (id, org_id, name, slug, repo_url)
      VALUES (${project}, ${org}, ${project}, ${slug}, 'https://eve.example/shop.git')
    `;
  });

  afterAll(async () => {
    await db`DELETE FROM jobs WHERE project_id = ${project}`;
    await db`DELETE FROM projects WHERE id = ${project}`;
    await db`DELETE FROM orgs WHERE id = ${org}`;
    await db.end({ timeout: 1 });
    await observer.end({ timeout: 1 });
  });

  it('refuse a reject racing an approve as already decided, and create no attempt 2', async () => {
    const id = await inReview();

    const reject = await race(id, approveAs('user_alice'), rejectAs('user_bob'));

    expect(reject.status).toBe('rejected');
    expect((reject as PromiseRejectedResult).reason).toBeInstanceOf(ReviewDecidedError);
    expect(await state(id)).toEqual({ phase: 'done', review_status: 'approved', reviewer: 'user_alice', attempts: [1] });
  });

  it('refuse an approve racing a reject as already decided', async () => {
    const id = await inReview();

    const approve = await race(id, rejectAs('user_alice'), approveAs('user_bob'));

    expect(approve.status).toBe('rejected');
    expect((approve as PromiseRejectedResult).reason).toBeInstanceOf(ReviewDecidedError);
    expect(await state(id)).toEqual({ phase: 'active', review_status: 'rejected', reviewer: 'user_alice', attempts: [1, 2] });
  });

  it('refuse the second of two racing approves', async () => {
    const id = await inReview();

    const second = await race(id, approveAs('user_alice'), approveAs('user_bob'));

    expect(second.status).toBe('rejected');
    expect((second as PromiseRejectedResult).reason).toBeInstanceOf(ReviewDecidedError);
    expect(await state(id)).toEqual({ phase: 'done', review_status: 'approved', reviewer: 'user_alice', attempts: [1] });
  });

  it('refuse a decision on a review decided earlier as already decided', async () => {
    const id = await inReview();
    await approveAs('user_alice')(jobQueries(db), id);

    await expect(rejectAs('user_bob')(jobQueries(db), id)).rejects.toBeInstanceOf(ReviewDecidedError);
    await expect(approveAs('user_bob')(jobQueries(db), id)).rejects.toBeInstanceOf(ReviewDecidedError);
    expect(await state(id)).toEqual({ phase: 'done', review_status: 'approved', reviewer: 'user_alice', attempts: [1] });
  });

  it('still refuse a decision on a job never sent for review, as not in review', async () => {
    const id = await inReview();
    await db`UPDATE jobs SET phase = 'active', review_status = NULL WHERE id = ${id}`;

    const refused = approveAs('user_alice')(jobQueries(db), id);

    await expect(refused).rejects.toThrow(/must be in 'review' phase/);
    await expect(refused).rejects.not.toBeInstanceOf(ReviewDecidedError);
  });

  /** Rejects the review of attempt 1; attempt 2 runs and is sent for review. Returns both attempts' ids. */
  async function backInReview(id: string): Promise<{ first: string; second: string }> {
    await rejectAs('user_alice')(jobQueries(db), id);
    await db`UPDATE job_attempts SET status = 'succeeded' WHERE job_id = ${id} AND attempt_number = 2`;
    await db`UPDATE jobs SET phase = 'review', review_status = 'pending' WHERE id = ${id}`;
    const rows = await db<Array<{ id: string; attempt_number: number }>>`
      SELECT id, attempt_number FROM job_attempts WHERE job_id = ${id} ORDER BY attempt_number
    `;
    return { first: String(rows[0].id), second: String(rows[1].id) };
  }

  it('refuse a decision on the round before, once the job is back in review on a later attempt', async () => {
    const id = await inReview();
    const { first } = await backInReview(id);

    const approve = jobQueries(db).approveReview(id, 'user_bob', 'looks right', 'user', { attemptId: first });
    await expect(approve).rejects.toBeInstanceOf(ReviewRoundChangedError);
    await expect(approve).rejects.toBeInstanceOf(ReviewDecidedError);
    await expect(jobQueries(db).rejectReview(id, 'user_bob', 'count again', 'user', { attemptId: first }))
      .rejects.toBeInstanceOf(ReviewRoundChangedError);
    expect(await state(id)).toEqual({ phase: 'review', review_status: 'pending', reviewer: 'user_alice', attempts: [1, 2] });
  });

  it('decide the round the decider names when it is the one in review', async () => {
    const id = await inReview();
    const { second } = await backInReview(id);

    await jobQueries(db).approveReview(id, 'user_bob', 'looks right', 'user', { attemptId: second });

    expect(await state(id)).toEqual({ phase: 'done', review_status: 'approved', reviewer: 'user_bob', attempts: [1, 2] });
  });
});
