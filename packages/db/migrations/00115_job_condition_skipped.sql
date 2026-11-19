-- Migration: when a workflow step was skipped by its own condition
-- Description: Set only by the orchestrator when it skips a step whose
-- condition is not met. A step whose condition names a skipped step skips
-- too. The jobs API never sets it, so closing a job as done by hand does not
-- count as a skip. Steps skipped before this migration are marked from their
-- close reason.

-- Fail fast rather than queue behind a long transaction on jobs; the runner
-- applies each migration in its own transaction, so this holds for it only.
SET LOCAL lock_timeout = '5s';

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS condition_skipped_at TIMESTAMPTZ;

UPDATE jobs
SET condition_skipped_at = COALESCE(closed_at, updated_at)
WHERE phase = 'done'
  AND close_reason = 'condition_not_met'
  AND step_name IS NOT NULL
  AND condition_skipped_at IS NULL;

COMMENT ON COLUMN jobs.condition_skipped_at IS 'When the orchestrator skipped this workflow step because its condition was not met (NULL: not skipped by its condition)';
