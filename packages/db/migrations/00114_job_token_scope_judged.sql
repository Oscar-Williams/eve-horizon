-- Migration: when a job's token scope was judged
-- Description: Set by the API when a job's declared token scope was judged
-- for the user who started the work and sits inside what the org's strict
-- security profile allows (P1-6). NULL means it was not judged: no user
-- started the work, the scope was only recorded, or the job predates the
-- check. The orchestrator then decides, under the org's profile, whether the
-- job's workspace and token may carry org files, docs or cloud-fs.

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS token_scope_judged_at TIMESTAMPTZ;

COMMENT ON COLUMN jobs.token_scope_judged_at IS 'When the declared token scope was judged against the starting user and found inside the org strict profile (NULL: not judged)';
