-- 00124_managed_db_tenant_schema_owners.sql
-- Schema-owner roles: a declared managed DB role may own one named schema of
-- its tenant database (manifest `grants: { schema: <name>, owner: true }`),
-- with DDL there and nothing in `public`. One row per provisioned role,
-- credentials stored as in managed_db_tenant_roles. The intent stays in
-- managed_db_tenants.desired_roles, as an object grant.
--
-- The rows live apart from managed_db_tenant_roles on purpose: a release
-- before 0.1.330 reads that table only, and would drop (or rotate) any role
-- it holds that its manifest parser cannot read. Here, it never sees them.
--
-- Rollback (0.1.329 or earlier after this migration): the runner skips
-- migrations it does not know, and nothing in that release reads this table,
-- so it runs unchanged. Its declared-role list (desired_roles, read through
-- a normaliser that drops object grants) and its provisioned list
-- (managed_db_tenant_roles) both leave the owner role out, so it neither
-- drops, rotates, regrants nor disconnects that login: the role keeps its
-- schema and its password, and running services keep working. What it
-- cannot do: deploy or sync a manifest that declares an owner role (it
-- refuses the object grant), so such a project deploys again only on 0.1.330
-- or later; and `eve db destroy` there drops the database but leaves the
-- owner login behind, which the operator drops by hand (`DROP ROLE`). To roll
-- back cleanly, remove the role from the manifest and deploy under 0.1.330
-- first: Eve hands the schema back to the tenant owner, then drops the login.

-- The foreign key takes a lock on managed_db_tenants: do not queue behind a
-- long transaction holding it.
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS managed_db_tenant_schema_owners (
  id                    TEXT PRIMARY KEY,                    -- mdbr_xxx (TypeID)
  tenant_id             TEXT NOT NULL REFERENCES managed_db_tenants(id) ON DELETE CASCADE,
  name                  TEXT NOT NULL,                       -- manifest role name
  schema_name           TEXT NOT NULL,                       -- the schema it owns
  db_user               TEXT NOT NULL,                       -- <tenant db_user>-<name>, 63-char safe
  credential_secret_ref TEXT,
  created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at            TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  CONSTRAINT managed_db_tenant_schema_owners_schema CHECK (
    schema_name ~ '^[a-z_][a-z0-9_]{0,62}$'
    AND schema_name <> 'public'
    AND schema_name <> 'information_schema'
    AND schema_name NOT LIKE 'pg\_%'
  ),
  UNIQUE (tenant_id, name),
  UNIQUE (tenant_id, schema_name)
);
