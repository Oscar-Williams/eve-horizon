import type { Db } from '../client.js';

export interface RunnerResultRow {
  attempt_id: string;
  result: Record<string, unknown>;
  received_at: Date;
}

/**
 * Results runner pods report for their attempts. One per attempt: the first
 * report is kept and a later one refused.
 */
export function runnerResultQueries(db: Db) {
  return {
    /** Store an attempt's result; false when one is already stored. */
    async record(attemptId: string, result: Record<string, unknown>): Promise<boolean> {
      const rows = await db<{ attempt_id: string }[]>`
        INSERT INTO job_attempt_runner_results (attempt_id, result)
        VALUES (${attemptId}::uuid, ${db.json(result as never)}::jsonb)
        ON CONFLICT (attempt_id) DO NOTHING
        RETURNING attempt_id
      `;
      return rows.length > 0;
    },

    async find(attemptId: string): Promise<RunnerResultRow | null> {
      const [row] = await db<RunnerResultRow[]>`
        SELECT attempt_id, result, received_at FROM job_attempt_runner_results
        WHERE attempt_id = ${attemptId}::uuid
      `;
      return row ?? null;
    },
  };
}
