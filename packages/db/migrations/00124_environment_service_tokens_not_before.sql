-- 00124_environment_service_tokens_not_before.sql
-- `service_tokens_not_before`: the API refuses an environment's service
-- tokens, and the app-link tokens injected into its services, issued before
-- this time (whole seconds, like a token's `iat`). Null: no floor.
-- `eve env rotate-service-tokens` sets it to now, and the worker then renews
-- the environment's tokens.
--
-- Rollback: the previous release never reads the column (it reads
-- environments with SELECT * and ignores fields it does not know), so it runs
-- unchanged after this migration. It then accepts tokens issued before the
-- floor again until they expire; rotate again after re-upgrading.

-- Do not queue behind a long transaction holding the table.
SET LOCAL lock_timeout = '5s';

-- Nullable with no default: a catalog-only change, no table rewrite.
ALTER TABLE environments ADD COLUMN IF NOT EXISTS service_tokens_not_before TIMESTAMPTZ;
