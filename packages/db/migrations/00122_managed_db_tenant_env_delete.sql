-- 00122_managed_db_tenant_env_delete.sql
-- Deleting an environment keeps its managed database tenants: each is queued
-- for drop (status 'deleting'), and its env_id becomes NULL when the
-- environment row goes, instead of the delete failing on the foreign key or
-- a forced delete removing the tenant row and leaving the database behind.
-- The reconciler drops the database and marks the tenant deleted.
--
-- Rollback: the previous release reads env_id only through joins and
-- `env_id = $1` filters, so tenants with a NULL env_id are simply not found
-- by environment; its reconciler still drops them by status.

-- Do not queue behind a long transaction holding the table.
SET LOCAL lock_timeout = '5s';

ALTER TABLE managed_db_tenants ALTER COLUMN env_id DROP NOT NULL;

ALTER TABLE managed_db_tenants DROP CONSTRAINT IF EXISTS managed_db_tenants_env_id_fkey;
ALTER TABLE managed_db_tenants
  ADD CONSTRAINT managed_db_tenants_env_id_fkey
  FOREIGN KEY (env_id) REFERENCES environments(id) ON DELETE SET NULL;

-- A tenant's snapshots outlive its environment (a pre-delete snapshot is
-- taken after the environment row is gone, and is what a restore needs).
ALTER TABLE managed_db_snapshots ALTER COLUMN env_id DROP NOT NULL;

ALTER TABLE managed_db_snapshots DROP CONSTRAINT IF EXISTS managed_db_snapshots_env_id_fkey;
ALTER TABLE managed_db_snapshots
  ADD CONSTRAINT managed_db_snapshots_env_id_fkey
  FOREIGN KEY (env_id) REFERENCES environments(id) ON DELETE SET NULL;
