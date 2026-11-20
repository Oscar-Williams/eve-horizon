-- Migration: a profile changed without its stamp drops the stamp
-- Description: Releases before profile stamps (0.1.326 and earlier) set
-- `security_profile` on orgs and projects without knowing
-- `security_profile_ruleset`. After a rollback, such a release could move a
-- project stamped 2 from audit back to strict and leave the stamp, so a
-- re-upgrade would enforce the rule set 2 rules with no audit window. A
-- trigger clears the stamp whenever an UPDATE changes `security_profile` and
-- leaves `security_profile_ruleset` as it was; a NULL stamp on a strict row
-- reads as rule set 1. This release always writes both columns together, and
-- writes a new stamp whenever it sets strict, so its own writes keep theirs.
-- The instance setting is not covered: the instance goes strict only after
-- re-encryption, which already rules out a rollback below 0.1.327.

-- Do not queue behind a long transaction holding the tables.
SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION security_profile_stamp_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.security_profile IS DISTINCT FROM OLD.security_profile
     AND NEW.security_profile_ruleset IS NOT DISTINCT FROM OLD.security_profile_ruleset THEN
    NEW.security_profile_ruleset := NULL;
  END IF;
  RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS orgs_security_profile_stamp_guard ON orgs;
CREATE TRIGGER orgs_security_profile_stamp_guard
  BEFORE UPDATE OF security_profile ON orgs
  FOR EACH ROW EXECUTE FUNCTION security_profile_stamp_guard();

DROP TRIGGER IF EXISTS projects_security_profile_stamp_guard ON projects;
CREATE TRIGGER projects_security_profile_stamp_guard
  BEFORE UPDATE OF security_profile ON projects
  FOR EACH ROW EXECUTE FUNCTION security_profile_stamp_guard();
