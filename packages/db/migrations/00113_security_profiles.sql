-- Migration: security profiles
-- Description: A security profile (legacy, audit, strict) decides whether a
-- hardening rule is ignored, recorded or enforced. It is set on the instance
-- (system_settings 'security.profile'), an org or a project; a project
-- overrides its org and an org overrides the instance. Existing installs
-- start on 'audit': today's behaviour, plus a record of what 'strict' would
-- refuse. Only system admins change profiles.

ALTER TABLE orgs ADD COLUMN IF NOT EXISTS security_profile TEXT;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS security_profile TEXT;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'orgs_security_profile_check') THEN
    ALTER TABLE orgs ADD CONSTRAINT orgs_security_profile_check
      CHECK (security_profile IS NULL OR security_profile IN ('legacy', 'audit', 'strict'));
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'projects_security_profile_check') THEN
    ALTER TABLE projects ADD CONSTRAINT projects_security_profile_check
      CHECK (security_profile IS NULL OR security_profile IN ('legacy', 'audit', 'strict'));
  END IF;
END $$;

COMMENT ON COLUMN orgs.security_profile IS 'legacy | audit | strict; NULL inherits the instance profile';
COMMENT ON COLUMN projects.security_profile IS 'legacy | audit | strict; NULL inherits the org profile';

INSERT INTO system_settings (key, value, description)
VALUES (
  'security.profile',
  'audit',
  'Instance security profile (legacy | audit | strict); orgs and projects may override it'
)
ON CONFLICT (key) DO NOTHING;

-- What a stricter profile refused or would refuse. One row per rule, scope,
-- actor and day; never holds a secret, token or request body.
CREATE TABLE IF NOT EXISTS security_findings (
  id TEXT PRIMARY KEY,
  day DATE NOT NULL,
  rule TEXT NOT NULL,
  profile TEXT NOT NULL,
  org_id TEXT,
  project_id TEXT,
  actor_type TEXT NOT NULL,
  actor_id TEXT NOT NULL,
  detail JSONB NOT NULL DEFAULT '{}'::jsonb,
  count INTEGER NOT NULL DEFAULT 1,
  first_seen TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  last_seen TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS security_findings_key
  ON security_findings (day, rule, COALESCE(org_id, ''), COALESCE(project_id, ''), actor_type, actor_id);
CREATE INDEX IF NOT EXISTS security_findings_last_seen ON security_findings (last_seen DESC);
