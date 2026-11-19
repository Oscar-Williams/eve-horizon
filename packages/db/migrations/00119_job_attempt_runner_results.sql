-- 00119_job_attempt_runner_results.sql
-- The result a runner pod reports for its attempt, once. A runner pod holds
-- no database credential: it pushes its result to the API with the attempt's
-- job token, and the worker records the attempt only when this row exists and
-- the pod has ended. The primary key makes a second report a conflict.

CREATE TABLE IF NOT EXISTS job_attempt_runner_results (
  attempt_id UUID PRIMARY KEY REFERENCES job_attempts(id) ON DELETE CASCADE,
  result JSONB NOT NULL,
  received_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE job_attempt_runner_results IS
  'The one result a runner pod reported for its attempt (push-only runner route)';
