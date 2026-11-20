-- 00122_project_manifest_synced_at.sql
-- `synced_at`: when a manifest row was last the subject of an explicit
-- `eve project sync` (the API, after its checks). The pipeline's drift check
-- also stores manifests, from whatever ref a build checked out, and a later
-- pipeline run for that ref can build and deploy a release from one, so
-- neither a row's `updated_at` nor a release pointing at it says who chose
-- it; runner egress allow lists (egress.allow_hosts) read the latest row by
-- `synced_at` only.
--
-- Backfill: rows an explicit sync wrote (the drift check leaves branch,
-- parsed_defaults and parsed_agents NULL). A project with no row matched
-- gets no project hosts until its next `eve project sync`.
--
-- Rollback: the previous release ignores the column.

-- Do not queue behind a long transaction holding the table.
SET LOCAL lock_timeout = '5s';

ALTER TABLE project_manifests ADD COLUMN IF NOT EXISTS synced_at TIMESTAMPTZ;

UPDATE project_manifests m
SET synced_at = m.updated_at
WHERE m.synced_at IS NULL
  AND (
    m.branch IS NOT NULL
    OR m.parsed_defaults IS NOT NULL
    OR m.parsed_agents IS NOT NULL
  );

CREATE INDEX IF NOT EXISTS idx_project_manifests_project_synced
  ON project_manifests (project_id, synced_at DESC)
  WHERE synced_at IS NOT NULL;
