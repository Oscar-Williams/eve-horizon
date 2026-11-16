-- Migration: a job's own secrets allowlist
-- Description: When set, an agent job receives only the secrets named here
-- (narrowed further by its agent's access.secrets). Set by the API from a
-- workflow step's `secrets:` and inherited by work a restricted job starts.
-- NULL means no allowlist of the job's own. Clients never set it directly.

ALTER TABLE jobs ADD COLUMN IF NOT EXISTS secrets_allowlist TEXT[];

COMMENT ON COLUMN jobs.secrets_allowlist IS 'Secret names an agent job may receive (NULL: no job-level allowlist); set by the API from workflow step secrets and inherited by work the job starts';
