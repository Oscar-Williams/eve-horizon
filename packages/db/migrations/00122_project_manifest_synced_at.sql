-- 00122_project_manifest_synced_at.sql
-- `synced_at`: when a manifest row was last the subject of an explicit
-- `eve project sync` (the API) or a deploy (the worker). The pipeline's
-- drift check also stores manifests, from whatever ref a build checked out,
-- so a row's `updated_at` says nothing about who chose it; runner egress
-- allow lists (egress.allow_hosts) read the latest row by `synced_at` only.
--
-- Backfill: rows a release points at (they were deployed), and rows an
-- explicit sync wrote (the drift check leaves branch, parsed_defaults and
-- parsed_agents NULL). A project with no row matched gets no project hosts
-- until its next sync or deploy.
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
    OR EXISTS (
      SELECT 1 FROM releases r
      WHERE r.project_id = m.project_id AND r.manifest_hash = m.manifest_hash
    )
  );

CREATE INDEX IF NOT EXISTS idx_project_manifests_project_synced
  ON project_manifests (project_id, synced_at DESC)
  WHERE synced_at IS NOT NULL;
