import { MANAGED_DB_SCHEMA_OWNER_GRANTS } from '@eve/shared';
import type { Db } from '../client.js';

// ---------------------------------------------------------------------------
// Instance types
// ---------------------------------------------------------------------------

export interface ManagedDbInstance {
  id: string;
  provider: string;
  provider_instance_id: string;
  region: string;
  engine: string;
  engine_version: string;
  host: string;
  port: number;
  instance_class: string;
  status: string;
  capacity_json: Record<string, unknown> | null;
  last_error_code: string | null;
  last_error_message: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface CreateManagedDbInstanceInput {
  id: string;
  provider: string;
  provider_instance_id: string;
  region: string;
  engine?: string;
  engine_version: string;
  host: string;
  port?: number;
  instance_class: string;
  capacity_json?: Record<string, unknown> | null;
}

// ---------------------------------------------------------------------------
// Tenant types
// ---------------------------------------------------------------------------

/**
 * Manifest intent for one declared tenant role (stored in
 * managed_db_tenants.desired_roles): `public` grants, or one schema the role
 * owns.
 */
export interface ManagedDbDesiredRole {
  name: string;
  grants: 'readwrite' | 'readonly' | { schema: string; owner: true };
}

export interface ManagedDbTenant {
  id: string;
  org_id: string;
  project_id: string;
  env_id: string | null;
  service_name: string;
  instance_id: string;
  provider_tenant_id: string | null;
  db_name: string;
  db_user: string;
  credential_secret_ref: string | null;
  class: string;
  desired_class: string | null;
  status: string;
  operation_token: string | null;
  last_error_code: string | null;
  last_error_message: string | null;
  desired_extensions: string[];
  enabled_extensions: string[];
  desired_roles: ManagedDbDesiredRole[];
  ready_at: Date | null;
  created_at: Date;
  updated_at: Date;
  deleted_at: Date | null;
  backup_schedule: string | null;
  backup_retention: string | null;
  snapshot_on_delete: boolean | null;
  snapshot_on_reset: boolean | null;
  last_snapshot_at: Date | null;
}

export interface CreateManagedDbTenantInput {
  id: string;
  org_id: string;
  project_id: string;
  env_id: string;
  service_name: string;
  instance_id: string;
  db_name: string;
  db_user: string;
  class: string;
  desired_extensions?: string[];
  desired_roles?: ManagedDbDesiredRole[];
}

/**
 * A provisioned tenant role login with its stored credential. A
 * schema-owner role has `grants = 'owner'` and the schema it owns in
 * `schema_name` (stored in managed_db_tenant_schema_owners, which releases
 * before 0.1.330 do not read); `public` data roles have `schema_name` null.
 */
export interface ManagedDbTenantRole {
  id: string;
  tenant_id: string;
  name: string;
  grants: string;
  schema_name: string | null;
  db_user: string;
  credential_secret_ref: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface UpsertManagedDbTenantRoleInput {
  id: string;
  tenant_id: string;
  name: string;
  /** `readwrite`, `readonly`, or `owner` with `schema_name`. */
  grants: string;
  schema_name?: string | null;
  db_user: string;
  credential_secret_ref: string | null;
}

// ---------------------------------------------------------------------------
// Query factory
// ---------------------------------------------------------------------------

/** The statuses a deleted tenant (deleted_at set) may still move to. */
const MANAGED_DB_STATUSES_ONCE_DELETED: readonly string[] = ['deleting', 'deleted', 'failed'];

export function managedDbQueries(db: Db) {
  return {
    // -----------------------------------------------------------------------
    // Instance CRUD
    // -----------------------------------------------------------------------

    async createInstance(input: CreateManagedDbInstanceInput): Promise<ManagedDbInstance> {
      const capacityJson = input.capacity_json
        ? db.json(input.capacity_json as never)
        : null;

      const [row] = await db<ManagedDbInstance[]>`
        INSERT INTO managed_db_instances (
          id, provider, provider_instance_id, region,
          engine, engine_version, host, port,
          instance_class, capacity_json
        )
        VALUES (
          ${input.id}, ${input.provider}, ${input.provider_instance_id}, ${input.region},
          ${input.engine ?? 'postgres'}, ${input.engine_version}, ${input.host}, ${input.port ?? 5432},
          ${input.instance_class}, ${capacityJson}
        )
        RETURNING *
      `;
      return row;
    },

    async findInstanceById(id: string): Promise<ManagedDbInstance | null> {
      const [row] = await db<ManagedDbInstance[]>`
        SELECT * FROM managed_db_instances WHERE id = ${id}
      `;
      return row ?? null;
    },

    async listInstances(opts?: { status?: string }): Promise<ManagedDbInstance[]> {
      const status = opts?.status ?? null;
      return db<ManagedDbInstance[]>`
        SELECT * FROM managed_db_instances
        WHERE (${status}::text IS NULL OR status = ${status})
        ORDER BY created_at DESC
      `;
    },

    async updateInstanceStatus(
      id: string,
      status: string,
      error?: { code: string; message: string } | null,
    ): Promise<ManagedDbInstance | null> {
      const errorCode = error?.code ?? null;
      const errorMessage = error?.message ?? null;
      const [row] = await db<ManagedDbInstance[]>`
        UPDATE managed_db_instances
        SET status = ${status},
            last_error_code = ${errorCode},
            last_error_message = ${errorMessage},
            updated_at = NOW()
        WHERE id = ${id}
        RETURNING *
      `;
      return row ?? null;
    },

    async updateInstanceCapacity(
      id: string,
      capacityJson: Record<string, unknown>,
    ): Promise<ManagedDbInstance | null> {
      const [row] = await db<ManagedDbInstance[]>`
        UPDATE managed_db_instances
        SET capacity_json = ${db.json(capacityJson as never)},
            updated_at = NOW()
        WHERE id = ${id}
        RETURNING *
      `;
      return row ?? null;
    },

    // -----------------------------------------------------------------------
    // Tenant CRUD
    // -----------------------------------------------------------------------

    async createTenant(input: CreateManagedDbTenantInput): Promise<ManagedDbTenant> {
      const desiredExtensions = input.desired_extensions ?? [];
      const desiredRoles = db.json((input.desired_roles ?? []) as never);
      const [row] = await db<ManagedDbTenant[]>`
        INSERT INTO managed_db_tenants (
          id, org_id, project_id, env_id, service_name,
          instance_id, db_name, db_user, class, desired_extensions, desired_roles
        )
        VALUES (
          ${input.id}, ${input.org_id}, ${input.project_id}, ${input.env_id}, ${input.service_name},
          ${input.instance_id}, ${input.db_name}, ${input.db_user}, ${input.class}, ${desiredExtensions}::text[],
          ${desiredRoles}
        )
        ON CONFLICT (env_id, service_name) DO NOTHING
        RETURNING *
      `;

      // Idempotent: return existing on conflict
      if (!row) {
        const [existing] = await db<ManagedDbTenant[]>`
          SELECT * FROM managed_db_tenants
          WHERE env_id = ${input.env_id} AND service_name = ${input.service_name}
        `;
        if (existing?.deleted_at) {
          if (existing.status !== 'deleted') {
            throw new Error(
              `Managed DB for service "${input.service_name}" is still being deleted (status ${existing.status}); ` +
              'deploy again once it is gone',
            );
          }
          // Destroyed and dropped: provision a fresh database in the same row
          // (the row keeps its id; the old database no longer exists).
          const [revived] = await db<ManagedDbTenant[]>`
            UPDATE managed_db_tenants
            SET instance_id = ${input.instance_id},
                db_name = ${input.db_name},
                db_user = ${input.db_user},
                class = ${input.class},
                desired_class = NULL,
                desired_extensions = ${desiredExtensions}::text[],
                enabled_extensions = '{}'::text[],
                desired_roles = ${desiredRoles},
                provider_tenant_id = NULL,
                credential_secret_ref = NULL,
                status = 'provisioning',
                operation_token = NULL,
                last_error_code = NULL,
                last_error_message = NULL,
                ready_at = NULL,
                deleted_at = NULL,
                updated_at = NOW()
            WHERE id = ${existing.id} AND status = 'deleted' AND deleted_at IS NOT NULL
            RETURNING *
          `;
          if (revived) return revived;
        }
        return existing;
      }
      return row;
    },

    async findTenantById(id: string): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        SELECT * FROM managed_db_tenants
        WHERE id = ${id} AND deleted_at IS NULL
      `;
      return row ?? null;
    },

    async findTenantByEnv(envId: string, serviceName: string): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        SELECT * FROM managed_db_tenants
        WHERE env_id = ${envId} AND service_name = ${serviceName} AND deleted_at IS NULL
      `;
      return row ?? null;
    },

    async listTenantsByOrg(orgId: string): Promise<ManagedDbTenant[]> {
      return db<ManagedDbTenant[]>`
        SELECT * FROM managed_db_tenants
        WHERE org_id = ${orgId} AND deleted_at IS NULL
        ORDER BY created_at DESC
      `;
    },

    async listTenantsByInstance(instanceId: string): Promise<ManagedDbTenant[]> {
      return db<ManagedDbTenant[]>`
        SELECT * FROM managed_db_tenants
        WHERE instance_id = ${instanceId} AND deleted_at IS NULL
        ORDER BY created_at DESC
      `;
    },

    async listTenantsByEnv(envId: string): Promise<ManagedDbTenant[]> {
      return db<ManagedDbTenant[]>`
        SELECT * FROM managed_db_tenants
        WHERE env_id = ${envId} AND deleted_at IS NULL
        ORDER BY created_at ASC
      `;
    },

    /**
     * Find orphaned tenants whose environment has been hard-deleted.
     * Used by the reconciler to detect and clean up stale tenants.
     */
    async findOrphanedTenants(): Promise<ManagedDbTenant[]> {
      return db<ManagedDbTenant[]>`
        SELECT t.* FROM managed_db_tenants t
        LEFT JOIN environments e ON e.id = t.env_id
        WHERE t.deleted_at IS NULL
          AND e.id IS NULL
        ORDER BY t.created_at ASC
      `;
    },

    /**
     * List tenants needing reconciliation (not in a terminal/ready state).
     * The reconciler polls this to find work.
     */
    async listTenantsNeedingReconciliation(): Promise<ManagedDbTenant[]> {
      // A deleted tenant in any status but deleted or failed is due its drop,
      // also one an operation left behind when the delete landed meanwhile.
      return db<ManagedDbTenant[]>`
        SELECT * FROM managed_db_tenants
        WHERE (deleted_at IS NULL AND status IN ('provisioning', 'modifying', 'rotating'))
           OR (status = 'deleting')
           OR (deleted_at IS NOT NULL AND status NOT IN ('deleted', 'failed'))
        ORDER BY created_at ASC
      `;
    },

    // -----------------------------------------------------------------------
    // Status transitions with operation locking
    // -----------------------------------------------------------------------

    /**
     * Acquire an operation lock on a tenant. Returns the tenant if lock was
     * acquired, null if already locked by another token.
     *
     * Only acquires if current operation_token is NULL (no active operation).
     * Allows locking soft-deleted tenants (status='deleting') so the
     * reconciler can finalize their cleanup.
     */
    async acquireOperationLock(
      tenantId: string,
      token: string,
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET operation_token = ${token},
            updated_at = NOW()
        WHERE id = ${tenantId}
          AND operation_token IS NULL
        RETURNING *
      `;
      return row ?? null;
    },

    /**
     * Release an operation lock. Only releases if the token matches.
     */
    async releaseOperationLock(
      tenantId: string,
      token: string,
    ): Promise<boolean> {
      const [row] = await db<{ id: string }[]>`
        UPDATE managed_db_tenants
        SET operation_token = NULL,
            updated_at = NOW()
        WHERE id = ${tenantId}
          AND operation_token = ${token}
        RETURNING id
      `;
      return !!row;
    },

    /**
     * Transition tenant status. Requires holding the operation lock (token match).
     * On success, clears the lock.
     *
     * A deleted tenant (deleted_at set, for example by an environment delete
     * while an operation held the lock) moves only to deleting, deleted or
     * failed; any other move is refused (null) and leaves the row and the
     * lock as they were.
     */
    async transitionStatus(
      tenantId: string,
      token: string,
      newStatus: string,
      opts?: {
        providerTenantId?: string;
        credentialSecretRef?: string;
        error?: { code: string; message: string } | null;
        setReady?: boolean;
        desiredClass?: string | null;
      },
    ): Promise<ManagedDbTenant | null> {
      const providerTenantId = opts?.providerTenantId ?? undefined;
      const credentialSecretRef = opts?.credentialSecretRef ?? undefined;
      const errorCode = opts?.error?.code ?? null;
      const errorMessage = opts?.error?.message ?? null;
      const readyAt = opts?.setReady ? new Date() : undefined;
      const allowedOnceDeleted = MANAGED_DB_STATUSES_ONCE_DELETED.includes(newStatus);

      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET status = ${newStatus},
            operation_token = NULL,
            last_error_code = ${errorCode},
            last_error_message = ${errorMessage},
            ${providerTenantId !== undefined ? db`provider_tenant_id = ${providerTenantId},` : db``}
            ${credentialSecretRef !== undefined ? db`credential_secret_ref = ${credentialSecretRef},` : db``}
            ${readyAt !== undefined ? db`ready_at = ${readyAt},` : db``}
            ${opts?.desiredClass !== undefined ? db`desired_class = ${opts.desiredClass},` : db``}
            updated_at = NOW()
        WHERE id = ${tenantId}
          AND operation_token = ${token}
          ${allowedOnceDeleted ? db`` : db`AND deleted_at IS NULL`}
        RETURNING *
      `;
      return row ?? null;
    },

    /**
     * End an operation that failed: `failed`, or `deleting` when the tenant
     * was deleted meanwhile (deleted_at set), so it stays queued for its
     * drop. One statement: a delete landing between a check and this write
     * can no longer park a deleted tenant at `failed` with its database
     * kept. Null when the caller no longer holds the lock or the row is gone.
     */
    async failOperation(
      tenantId: string,
      token: string,
      error: { code: string; message: string },
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET status = CASE WHEN deleted_at IS NULL THEN 'failed' ELSE 'deleting' END,
            operation_token = NULL,
            last_error_code = ${error.code},
            last_error_message = ${error.message},
            updated_at = NOW()
        WHERE id = ${tenantId}
          AND operation_token = ${token}
        RETURNING *
      `;
      return row ?? null;
    },

    /**
     * Soft-delete a tenant (set deleted_at).
     */
    async softDeleteTenant(tenantId: string): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET deleted_at = NOW(),
            status = 'deleting',
            updated_at = NOW()
        WHERE id = ${tenantId} AND deleted_at IS NULL
        RETURNING *
      `;
      return row ?? null;
    },

    /**
     * Hard-delete all managed_db_tenants rows for an environment.
     * Used during force env deletion to remove the FK constraint.
     */
    async hardDeleteTenantsByEnv(envId: string): Promise<number> {
      const rows = await db<{ id: string }[]>`
        DELETE FROM managed_db_tenants
        WHERE env_id = ${envId}
        RETURNING id
      `;
      return rows.length;
    },

    /**
     * Mark a deleted tenant as fully cleaned up (provider resources released).
     */
    async markTenantDeleted(tenantId: string): Promise<boolean> {
      const [row] = await db<{ id: string }[]>`
        UPDATE managed_db_tenants
        SET status = 'deleted',
            operation_token = NULL,
            updated_at = NOW()
        WHERE id = ${tenantId} AND deleted_at IS NOT NULL
        RETURNING id
      `;
      return !!row;
    },

    // -----------------------------------------------------------------------
    // Helpers for deployer and env-db resolver
    // -----------------------------------------------------------------------

    /**
     * Find the ready tenant for an environment. Used by deployer preflight
     * and env-db resolver to get connection details.
     */
    async findReadyTenantByEnv(
      envId: string,
      serviceName: string,
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        SELECT * FROM managed_db_tenants
        WHERE env_id = ${envId}
          AND service_name = ${serviceName}
          AND status = 'ready'
          AND deleted_at IS NULL
      `;
      return row ?? null;
    },

    /**
     * Force-release operation locks that have been held longer than the given
     * threshold. Uses `updated_at` (set to NOW() on lock acquisition) as a
     * proxy for lock age. No schema migration needed.
     */
    async forceReleaseStaleOperationLocks(
      thresholdMinutes: number,
    ): Promise<Array<{ id: string; operation_token: string }>> {
      return db<Array<{ id: string; operation_token: string }>>`
        UPDATE managed_db_tenants
        SET operation_token = NULL,
            updated_at = NOW()
        WHERE operation_token IS NOT NULL
          AND updated_at < NOW() - make_interval(mins => ${thresholdMinutes})
        RETURNING id, operation_token
      `;
    },

    /**
     * Count active tenants on an instance (for placement decisions).
     */
    async countActiveTenants(instanceId: string): Promise<number> {
      const [row] = await db<{ count: string }[]>`
        SELECT COUNT(*)::text AS count FROM managed_db_tenants
        WHERE instance_id = ${instanceId}
          AND deleted_at IS NULL
          AND status NOT IN ('deleting', 'failed')
      `;
      return parseInt(row?.count ?? '0', 10);
    },

    /**
     * List available instances with their active tenant counts in a single
     * query. Used by the placement service to score and select instances.
     */
    async listActiveInstancesWithCounts(): Promise<
      Array<{
        id: string;
        status: string;
        instance_class: string;
        capacity_json: Record<string, unknown> | null;
        tenant_count: number;
      }>
    > {
      return db<
        Array<{
          id: string;
          status: string;
          instance_class: string;
          capacity_json: Record<string, unknown> | null;
          tenant_count: number;
        }>
      >`
        SELECT i.id, i.status, i.instance_class, i.capacity_json,
               COALESCE(
                 (SELECT COUNT(*)::int FROM managed_db_tenants t
                  WHERE t.instance_id = i.id
                    AND t.deleted_at IS NULL
                    AND t.status NOT IN ('deleting', 'failed')),
                 0
               ) AS tenant_count
        FROM managed_db_instances i
        WHERE i.status = 'available'
        ORDER BY i.id
      `;
    },

    /**
     * Partial update of backup configuration columns on a tenant.
     * Uses COALESCE so that omitted (undefined/null) fields keep their
     * current DB value. Used by API actions that tweak a single field
     * (e.g., clearing snapshot_on_delete before destroy).
     */
    async updateTenantBackupConfig(
      tenantId: string,
      config: {
        backup_schedule?: string | null;
        backup_retention?: string | null;
        snapshot_on_delete?: boolean | null;
        snapshot_on_reset?: boolean | null;
      },
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET backup_schedule = COALESCE(${config.backup_schedule ?? null}::text, backup_schedule),
            backup_retention = COALESCE(${config.backup_retention ?? null}::text, backup_retention),
            snapshot_on_delete = COALESCE(${config.snapshot_on_delete ?? null}::boolean, snapshot_on_delete),
            snapshot_on_reset = COALESCE(${config.snapshot_on_reset ?? null}::boolean, snapshot_on_reset),
            updated_at = NOW()
        WHERE id = ${tenantId}
        RETURNING *
      `;
      return row ?? null;
    },

    /**
     * Full sync of backup configuration — every column is set to the
     * supplied value (including null, which clears the column).
     * Called by the deploy reconciler each deploy to keep the tenant
     * in lock-step with the manifest + class defaults.
     */
    async syncTenantBackupConfig(
      tenantId: string,
      config: {
        backup_schedule: string | null;
        backup_retention: string | null;
        snapshot_on_delete: boolean;
        snapshot_on_reset: boolean;
      },
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET backup_schedule = ${config.backup_schedule}::text,
            backup_retention = ${config.backup_retention}::text,
            snapshot_on_delete = ${config.snapshot_on_delete}::boolean,
            snapshot_on_reset = ${config.snapshot_on_reset}::boolean,
            updated_at = NOW()
        WHERE id = ${tenantId}
        RETURNING *
      `;
      return row ?? null;
    },

    async updateTenantCredentialSecretRef(
      tenantId: string,
      credentialSecretRef: string,
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET credential_secret_ref = ${credentialSecretRef},
            updated_at = NOW()
        WHERE id = ${tenantId}
        RETURNING *
      `;
      return row ?? null;
    },

    async syncTenantDesiredExtensions(
      tenantId: string,
      desiredExtensions: string[],
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET desired_extensions = ${desiredExtensions}::text[],
            updated_at = NOW()
        WHERE id = ${tenantId}
        RETURNING *
      `;
      return row ?? null;
    },

    async markTenantExtensionsEnabled(
      tenantId: string,
      token: string,
      enabledExtensions: string[],
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET enabled_extensions = ${enabledExtensions}::text[],
            updated_at = NOW()
        WHERE id = ${tenantId}
          AND operation_token = ${token}
        RETURNING *
      `;
      return row ?? null;
    },

    async syncTenantDesiredRoles(
      tenantId: string,
      desiredRoles: ManagedDbDesiredRole[],
    ): Promise<ManagedDbTenant | null> {
      const [row] = await db<ManagedDbTenant[]>`
        UPDATE managed_db_tenants
        SET desired_roles = ${db.json(desiredRoles as never)},
            updated_at = NOW()
        WHERE id = ${tenantId}
        RETURNING *
      `;
      return row ?? null;
    },

    // -----------------------------------------------------------------------
    // Tenant roles (declared least-privilege logins)
    // -----------------------------------------------------------------------

    /** Every provisioned role of the tenant, both kinds, by name. */
    async listTenantRoles(tenantId: string): Promise<ManagedDbTenantRole[]> {
      return db<ManagedDbTenantRole[]>`
        SELECT id, tenant_id, name, grants, NULL::text AS schema_name, db_user,
               credential_secret_ref, created_at, updated_at
        FROM managed_db_tenant_roles
        WHERE tenant_id = ${tenantId}
        UNION ALL
        SELECT id, tenant_id, name, ${MANAGED_DB_SCHEMA_OWNER_GRANTS} AS grants, schema_name, db_user,
               credential_secret_ref, created_at, updated_at
        FROM managed_db_tenant_schema_owners
        WHERE tenant_id = ${tenantId}
        ORDER BY name ASC
      `;
    },

    /**
     * Insert or refresh a provisioned role: a schema-owner role (`grants =
     * 'owner'` with `schema_name`) in managed_db_tenant_schema_owners, any
     * other in managed_db_tenant_roles. A null credential keeps the stored
     * one so callers can update grants without touching secrets.
     */
    async upsertTenantRole(input: UpsertManagedDbTenantRoleInput): Promise<ManagedDbTenantRole> {
      if (input.grants === MANAGED_DB_SCHEMA_OWNER_GRANTS) {
        if (!input.schema_name) throw new Error(`Schema-owner role ${input.name} needs the schema it owns`);
        const [owned] = await db<ManagedDbTenantRole[]>`
          INSERT INTO managed_db_tenant_schema_owners (
            id, tenant_id, name, schema_name, db_user, credential_secret_ref
          )
          VALUES (
            ${input.id}, ${input.tenant_id}, ${input.name}, ${input.schema_name}, ${input.db_user}, ${input.credential_secret_ref}
          )
          ON CONFLICT (tenant_id, name) DO UPDATE
          SET schema_name = EXCLUDED.schema_name,
              db_user = EXCLUDED.db_user,
              credential_secret_ref = COALESCE(EXCLUDED.credential_secret_ref, managed_db_tenant_schema_owners.credential_secret_ref),
              updated_at = NOW()
          RETURNING id, tenant_id, name, ${MANAGED_DB_SCHEMA_OWNER_GRANTS} AS grants, schema_name, db_user,
                    credential_secret_ref, created_at, updated_at
        `;
        return owned;
      }
      const [row] = await db<ManagedDbTenantRole[]>`
        INSERT INTO managed_db_tenant_roles (
          id, tenant_id, name, grants, db_user, credential_secret_ref
        )
        VALUES (
          ${input.id}, ${input.tenant_id}, ${input.name}, ${input.grants}, ${input.db_user}, ${input.credential_secret_ref}
        )
        ON CONFLICT (tenant_id, name) DO UPDATE
        SET grants = EXCLUDED.grants,
            db_user = EXCLUDED.db_user,
            credential_secret_ref = COALESCE(EXCLUDED.credential_secret_ref, managed_db_tenant_roles.credential_secret_ref),
            updated_at = NOW()
        RETURNING *, NULL::text AS schema_name
      `;
      return row;
    },

    async updateTenantRoleGrants(
      tenantId: string,
      name: string,
      grants: string,
    ): Promise<ManagedDbTenantRole | null> {
      const [row] = await db<ManagedDbTenantRole[]>`
        UPDATE managed_db_tenant_roles
        SET grants = ${grants},
            updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND name = ${name}
        RETURNING *, NULL::text AS schema_name
      `;
      return row ?? null;
    },

    /** New credential for a role of either kind. */
    async updateTenantRoleCredentialSecretRef(
      tenantId: string,
      name: string,
      credentialSecretRef: string,
    ): Promise<ManagedDbTenantRole | null> {
      const [row] = await db<ManagedDbTenantRole[]>`
        UPDATE managed_db_tenant_roles
        SET credential_secret_ref = ${credentialSecretRef},
            updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND name = ${name}
        RETURNING *, NULL::text AS schema_name
      `;
      if (row) return row;
      const [owned] = await db<ManagedDbTenantRole[]>`
        UPDATE managed_db_tenant_schema_owners
        SET credential_secret_ref = ${credentialSecretRef},
            updated_at = NOW()
        WHERE tenant_id = ${tenantId} AND name = ${name}
        RETURNING id, tenant_id, name, ${MANAGED_DB_SCHEMA_OWNER_GRANTS} AS grants, schema_name, db_user,
                  credential_secret_ref, created_at, updated_at
      `;
      return owned ?? null;
    },

    /** Forget a role of either kind. */
    async deleteTenantRole(tenantId: string, name: string): Promise<boolean> {
      const rows = await db<{ id: string }[]>`
        WITH roles AS (
          DELETE FROM managed_db_tenant_roles WHERE tenant_id = ${tenantId} AND name = ${name} RETURNING id
        ), owners AS (
          DELETE FROM managed_db_tenant_schema_owners WHERE tenant_id = ${tenantId} AND name = ${name} RETURNING id
        )
        SELECT id FROM roles UNION ALL SELECT id FROM owners
      `;
      return rows.length > 0;
    },

    /** Forget every role of the tenant, both kinds. */
    async deleteTenantRoles(tenantId: string): Promise<number> {
      const rows = await db<{ id: string }[]>`
        WITH roles AS (
          DELETE FROM managed_db_tenant_roles WHERE tenant_id = ${tenantId} RETURNING id
        ), owners AS (
          DELETE FROM managed_db_tenant_schema_owners WHERE tenant_id = ${tenantId} RETURNING id
        )
        SELECT id FROM roles UNION ALL SELECT id FROM owners
      `;
      return rows.length;
    },
  };
}
