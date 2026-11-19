-- 00118_environment_registry_key_version.sql
-- The registry key version that signed each environment's eve-registry pull
-- secret, and the pull epoch it was recorded at. The deployer and
-- `eve system security reconcile` record them once the secret is written.
--
-- An environment with a pull epoch above 0 has had an Eve pull secret. It is
-- on the current key only when its version is the current key's version and
-- was recorded at its current epoch: a write that did not record a version
-- (a release before this one) leaves it stale until reconcile checks it.
-- The instance goes strict (registry.internal_key) and the legacy internal
-- key is removed only once no environment is stale.

ALTER TABLE environments
  ADD COLUMN IF NOT EXISTS registry_key_version TEXT,
  ADD COLUMN IF NOT EXISTS registry_key_epoch INTEGER;

COMMENT ON COLUMN environments.registry_key_version IS
  'Version of the registry credential key that signed the pull secret (internal for EVE_INTERNAL_API_KEY); NULL when none was recorded';
COMMENT ON COLUMN environments.registry_key_epoch IS
  'registry_pull_epoch when registry_key_version was recorded';
