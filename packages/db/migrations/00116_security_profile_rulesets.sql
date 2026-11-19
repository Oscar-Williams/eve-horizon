-- Migration: security profile stamps
-- Description: A `strict` profile covers the rule set current when it was
-- set (P1 is 1, P2 is 2). A rule from a later rule set runs under `audit`
-- there until `strict` is set again. The stamp lives next to each profile:
-- `security_profile_ruleset` on orgs and projects, and the instance setting
-- 'security.profile_ruleset'. Profiles already `strict` were set under the
-- P1 rules, so they are stamped 1. NULL on a `strict` row also reads as 1.

-- Fail fast rather than queue behind a long transaction; the runner applies
-- each migration in its own transaction, so this holds for it only.
SET LOCAL lock_timeout = '5s';

ALTER TABLE orgs ADD COLUMN IF NOT EXISTS security_profile_ruleset INTEGER;
ALTER TABLE projects ADD COLUMN IF NOT EXISTS security_profile_ruleset INTEGER;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'orgs_security_profile_ruleset_check') THEN
    ALTER TABLE orgs ADD CONSTRAINT orgs_security_profile_ruleset_check
      CHECK (security_profile_ruleset IS NULL OR security_profile_ruleset >= 1);
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'projects_security_profile_ruleset_check') THEN
    ALTER TABLE projects ADD CONSTRAINT projects_security_profile_ruleset_check
      CHECK (security_profile_ruleset IS NULL OR security_profile_ruleset >= 1);
  END IF;
END $$;

COMMENT ON COLUMN orgs.security_profile_ruleset IS 'Rule set a strict profile covers (P1 = 1); later rules run under audit. NULL reads as 1';
COMMENT ON COLUMN projects.security_profile_ruleset IS 'Rule set a strict profile covers (P1 = 1); later rules run under audit. NULL reads as 1';

UPDATE orgs SET security_profile_ruleset = 1
WHERE security_profile = 'strict' AND security_profile_ruleset IS NULL;

UPDATE projects SET security_profile_ruleset = 1
WHERE security_profile = 'strict' AND security_profile_ruleset IS NULL;

INSERT INTO system_settings (key, value, description)
SELECT 'security.profile_ruleset', '1', 'Rule set the instance strict profile covers; later rules run under audit'
FROM system_settings
WHERE key = 'security.profile' AND value = 'strict'
ON CONFLICT (key) DO NOTHING;
