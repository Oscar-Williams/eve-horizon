import { Injectable, Inject, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { CronJob } from 'cron';
import {
  managedDbQueries,
  managedDbSnapshotQueries,
  createPinnedSearchPathDb,
  checkManagedDbSchemaClaim,
  claimManagedDbSchema,
  releaseManagedDbSchema,
  ManagedDbSchemaConflictError,
  type Db,
  type ManagedDbSchemaTarget,
  type ManagedDbTenantRole,
  orgQueries,
  projectQueries,
  environmentQueries,
} from '@eve/db';
import {
  generateManagedDbInstanceId,
  generateManagedDbRoleUser,
  generateManagedDbSnapshotId,
  generateManagedDbTenantRoleId,
  getManagedDbLimits,
  managedDbDatabaseConnectionLimit,
  createSnapshotStorageClient,
  executeSnapshot,
  resolveManagedDbSnapshotRetention,
  snapshotRetentionToExpiresAt,
  buildSnapshotS3Key,
  getSupportedExtensionDefinition,
  isSupportedExtensionName,
  isManagedDbExtensionEnabled,
  MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV,
  normalizeManagedDbExtensions,
  quotePostgresIdentifier,
  sharedPreloadLibrariesContains,
  buildManagedDbRoleGrantSql,
  buildManagedDbRoleRevokeSql,
  buildManagedDbSchemaOwnerSql,
  diffManagedDbRoles,
  hasManagedDbRoleChanges,
  isManagedDbRoleGrants,
  managedDbRoleOwnedSchema,
  MANAGED_DB_SCHEMA_OWNER_GRANTS,
  normalizeManagedDbRoles,
  type ManagedDbRoleDeclaration,
  type ManagedDbRoleDiff,
  type ManagedDbRoleGrants,
  type SupportedExtension,
} from '@eve/shared';
import * as crypto from 'crypto';

class ManagedDbProvisioningError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}

/**
 * Managed DB Reconciler
 *
 * Periodically scans managed_db_tenants for tenants in transitional states
 * (provisioning, modifying, rotating, deleting) and drives them forward
 * via the provider contract.
 *
 * For local provider: runs CREATE DATABASE / CREATE ROLE on the system Postgres.
 * For cloud providers: will call the provider API (future).
 *
 * Disabled by default; enable with EVE_MANAGED_DB_RECONCILER_ENABLED=true.
 */
@Injectable()
export class ManagedDbReconcilerService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ManagedDbReconcilerService.name);
  private cronJob: CronJob | null = null;
  private reconciling = false;
  /** The one-off isolation pass over existing tenants, started at boot. */
  private isolationBackfill: Promise<void> | null = null;

  private readonly managedDb: ReturnType<typeof managedDbQueries>;
  private readonly snapshots: ReturnType<typeof managedDbSnapshotQueries>;
  private readonly orgs: ReturnType<typeof orgQueries>;
  private readonly projects: ReturnType<typeof projectQueries>;
  private readonly environments: ReturnType<typeof environmentQueries>;

  constructor(@Inject('DB') private readonly db: Db) {
    this.managedDb = managedDbQueries(db);
    this.snapshots = managedDbSnapshotQueries(db);
    this.orgs = orgQueries(db);
    this.projects = projectQueries(db);
    this.environments = environmentQueries(db);
  }

  async onModuleInit(): Promise<void> {
    if (process.env.EVE_MANAGED_DB_RECONCILER_ENABLED !== 'true') {
      this.logger.log('[managed-db-reconciler] Disabled (set EVE_MANAGED_DB_RECONCILER_ENABLED=true to enable)');
      return;
    }

    // Seed local instance if requested
    if (process.env.EVE_MANAGED_DB_LOCAL_SEED === 'true') {
      await this.seedLocalInstance();
    }

    // Tenants provisioned before isolation existed get it once, in the
    // background, so a slow instance cannot hold up start-up.
    this.isolationBackfill = this.isolateReadyTenants().catch((err) => {
      this.logger.error(`[managed-db-reconciler] Isolation pass failed: ${err instanceof Error ? err.message : String(err)}`);
    });

    const cron = process.env.EVE_MANAGED_DB_RECONCILER_CRON ?? '*/30 * * * * *';

    try {
      this.cronJob = new CronJob(
        cron,
        () => {
          this.reconcile().catch((err) => {
            this.logger.error(`[managed-db-reconciler] Reconcile failed: ${err instanceof Error ? err.message : String(err)}`);
          });
        },
        null,
        true,
        'UTC',
      );
      this.logger.log(`[managed-db-reconciler] Enabled (cron="${cron}")`);
    } catch (err) {
      this.logger.error(`[managed-db-reconciler] Failed to start cron: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.cronJob) {
      try { this.cronJob.stop(); } catch { /* ignore */ }
      this.cronJob = null;
    }
  }

  /**
   * Main reconciliation loop. Finds tenants needing work and processes them.
   */
  async reconcile(): Promise<void> {
    if (this.reconciling) return; // Prevent overlap
    this.reconciling = true;

    try {
      // Release locks held longer than 10 minutes (crash recovery)
      const stale = await this.managedDb.forceReleaseStaleOperationLocks(10);
      if (stale.length > 0) {
        this.logger.warn(`[managed-db-reconciler] Released ${stale.length} stale lock(s): ${stale.map(s => s.id).join(', ')}`);
      }

      const tenants = await this.managedDb.listTenantsNeedingReconciliation();
      if (tenants.length > 0) {
        this.logger.log(`[managed-db-reconciler] Processing ${tenants.length} tenant(s)`);

        for (const tenant of tenants) {
          try {
            await this.reconcileTenant(tenant);
          } catch (err) {
            this.logger.error(`[managed-db-reconciler] Failed to reconcile tenant ${tenant.id}: ${err instanceof Error ? err.message : String(err)}`);
          }
        }
      }

      // Orphan reconciliation
      await this.reconcileOrphans();
    } finally {
      this.reconciling = false;
    }
  }

  /**
   * Find and clean up orphaned tenants whose environment has been deleted.
   * Called at the end of each reconciliation cycle.
   */
  private async reconcileOrphans(): Promise<void> {
    const orphans = await this.managedDb.findOrphanedTenants();
    if (orphans.length === 0) return;

    this.logger.log(`[managed-db-reconciler] Found ${orphans.length} orphaned tenant(s)`);

    for (const orphan of orphans) {
      try {
        if (orphan.status !== 'deleting') {
          await this.managedDb.softDeleteTenant(orphan.id);
          this.logger.log(`[managed-db-reconciler] Marked orphan ${orphan.id} for deletion`);
        }
      } catch (err) {
        this.logger.error(`[managed-db-reconciler] Failed to clean up orphan ${orphan.id}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }
  }

  private async reconcileTenant(tenant: {
    id: string;
    status: string;
    instance_id: string;
    db_name: string;
    db_user: string;
    class: string;
    desired_class: string | null;
    provider_tenant_id: string | null;
    credential_secret_ref: string | null;
    snapshot_on_delete: boolean | null;
    org_id: string;
    project_id: string;
    env_id: string | null;
    backup_retention: string | null;
    desired_extensions: string[];
    enabled_extensions: string[];
    desired_roles: ManagedDbRoleDeclaration[];
    deleted_at?: Date | string | null;
    updated_at?: Date | string | null;
    last_error_code?: string | null;
  }): Promise<void> {
    if ((tenant.status === 'deleting' || tenant.deleted_at) && !dropAttemptDue(tenant)) return;

    const token = crypto.randomUUID();
    const locked = await this.managedDb.acquireOperationLock(tenant.id, token);
    if (!locked) {
      this.logger.log(`[managed-db-reconciler] Tenant ${tenant.id} locked by another operation, skipping`);
      return;
    }

    // A deleted tenant is dropped whatever its status: an operation that was
    // running when the delete landed can leave it in another one.
    const dropping = tenant.status === 'deleting' || !!tenant.deleted_at;

    try {
      if (dropping) {
        await this.handleDeleting(tenant, token);
        return;
      }
      switch (tenant.status) {
        case 'provisioning':
          await this.handleProvisioning(tenant, token);
          break;
        case 'modifying':
          await this.handleModifying(tenant, token);
          break;
        case 'rotating':
          await this.handleRotating(tenant, token);
          break;
        default:
          // Release lock for unknown states
          await this.managedDb.releaseOperationLock(tenant.id, token);
      }
    } catch (err) {
      const error = err instanceof ManagedDbProvisioningError
        ? { code: err.code, message: err.message }
        : {
            code: 'reconcile_error',
            message: err instanceof Error ? err.message : String(err),
          };
      // A drop that fails stays queued (lock released, error recorded) for
      // a day, so a busy database or a passing outage does not strand it,
      // and parks at failed after that. Any other operation parks at failed
      // unless the tenant was deleted meanwhile (failOperation).
      if (dropping && withinDropRetryWindow(tenant.deleted_at)) {
        this.logger.warn(`[managed-db-reconciler] Drop of tenant ${tenant.id} failed; will retry: ${error.message}`);
        await this.managedDb.transitionStatus(tenant.id, token, 'deleting', { error });
        return;
      }
      if (dropping) {
        await this.managedDb.transitionStatus(tenant.id, token, 'failed', { error });
        return;
      }
      await this.failOperation(tenant.id, token, error);
    }
  }

  /**
   * An operation (not a drop) failed: the tenant parks at failed, or, when it
   * was deleted meanwhile, whenever the delete landed, stays queued for its
   * drop instead of keeping its database (failOperation decides in one
   * statement).
   */
  private async failOperation(tenantId: string, token: string, error: { code: string; message: string }): Promise<void> {
    const row = await this.managedDb.failOperation(tenantId, token, error);
    if (row?.status === 'deleting') {
      this.logger.warn(`[managed-db-reconciler] Tenant ${tenantId} was deleted during a failed operation; queued for drop: ${error.message}`);
    }
  }

  /**
   * Moves a tenant on at the end of an operation. A tenant deleted meanwhile
   * cannot move (transitionStatus refuses); its lock is released so the next
   * pass drops it.
   */
  private async completeOperation(
    tenantId: string,
    token: string,
    status: string,
    opts?: Parameters<ReturnType<typeof managedDbQueries>['transitionStatus']>[3],
  ): Promise<void> {
    const moved = await this.managedDb.transitionStatus(tenantId, token, status, opts);
    if (!moved && (await this.managedDb.releaseOperationLock(tenantId, token))) {
      this.logger.log(`[managed-db-reconciler] Tenant ${tenantId} was deleted during the operation; it will be dropped`);
    }
  }

  private async handleProvisioning(
    tenant: {
      id: string;
      instance_id: string;
      db_name: string;
      db_user: string;
      class: string;
      desired_extensions: string[];
      enabled_extensions: string[];
      desired_roles: ManagedDbRoleDeclaration[];
    },
    token: string,
  ): Promise<void> {
    const instance = await this.managedDb.findInstanceById(tenant.instance_id);
    if (!instance) {
      await this.failOperation(tenant.id, token, {
        code: 'instance_not_found',
        message: `Instance ${tenant.instance_id} not found`,
      });
      return;
    }

    this.logger.log(
      `[managed-db-reconciler] Provisioning tenant ${tenant.id} on instance ${instance.id} ` +
      `(${instance.provider}/${instance.provider_instance_id})`,
    );

    const desiredExtensions = normalizeManagedDbExtensions(tenant.desired_extensions, {
      includeDisabledProviderGated: true,
    });
    if (instance.provider === 'local') {
      const connectionUrl = await this.provisionLocalDb(instance, tenant);
      if (desiredExtensions.length > 0) {
        await this.installTenantExtensions(instance, tenant, desiredExtensions);
        await this.managedDb.markTenantExtensionsEnabled(
          tenant.id,
          token,
          this.mergeEnabledExtensions(tenant.enabled_extensions, desiredExtensions),
        );
      }
      await this.applyLocalTenantRoleChanges(instance, tenant, withOwnerRolesSetUpAgain(await this.planTenantRoleChanges(tenant)));
      await this.completeOperation(tenant.id, token, 'ready', {
        providerTenantId: `local:${tenant.db_name}`,
        credentialSecretRef: connectionUrl,
        setReady: true,
      });
      this.logger.log(`[managed-db-reconciler] Tenant ${tenant.id} provisioned (local: ${tenant.db_name})`);
    } else {
      // Only the local provider creates real databases. Marking a tenant
      // ready here would hand the app a database that does not exist.
      throw new ManagedDbProvisioningError(
        'provider_unsupported',
        `Managed DB provisioning is not implemented for provider "${instance.provider}"; ` +
        'register a local instance (EVE_MANAGED_DB_LOCAL_SEED) or use a database override',
      );
    }
  }

  private async handleModifying(
    tenant: {
      id: string;
      instance_id: string;
      db_name: string;
      db_user: string;
      class: string;
      desired_class: string | null;
      desired_extensions: string[];
      enabled_extensions: string[];
      desired_roles: ManagedDbRoleDeclaration[];
    },
    token: string,
  ): Promise<void> {
    const missingExtensions = this.getMissingExtensions(tenant.desired_extensions, tenant.enabled_extensions);
    if (missingExtensions.length > 0) {
      const instance = await this.managedDb.findInstanceById(tenant.instance_id);
      if (!instance) {
        throw new ManagedDbProvisioningError('instance_not_found', `Instance ${tenant.instance_id} not found`);
      }
      if (instance.provider !== 'local') {
        throw new ManagedDbProvisioningError(
          'provider_unsupported',
          `Managed DB extension provisioning is not implemented for provider "${instance.provider}"`,
        );
      }

      this.logger.log(
        `[managed-db-reconciler] Installing extension(s) for tenant ${tenant.id}: ` +
        missingExtensions.join(', '),
      );
      await this.installTenantExtensions(instance, tenant, missingExtensions);
      await this.managedDb.markTenantExtensionsEnabled(
        tenant.id,
        token,
        this.mergeEnabledExtensions(tenant.enabled_extensions, missingExtensions),
      );
    }

    const rolePlan = await this.planTenantRoleChanges(tenant);
    // Schema-owner roles are checked on every run, not only when roles change.
    if (hasManagedDbRoleChanges(rolePlan.diff) || ownsSchemas(rolePlan.desired)) {
      const instance = await this.managedDb.findInstanceById(tenant.instance_id);
      if (!instance) {
        throw new ManagedDbProvisioningError('instance_not_found', `Instance ${tenant.instance_id} not found`);
      }
      if (instance.provider !== 'local') {
        throw new ManagedDbProvisioningError(
          'provider_unsupported',
          `Managed DB role provisioning is not implemented for provider "${instance.provider}"`,
        );
      }

      if (hasManagedDbRoleChanges(rolePlan.diff)) {
        this.logger.log(
          `[managed-db-reconciler] Reconciling role(s) for tenant ${tenant.id}: ` +
          this.describeRolePlan(rolePlan.diff),
        );
      }
      await this.applyLocalTenantRoleChanges(instance, tenant, rolePlan);
    }

    // Isolation is applied again on every change (idempotent), so a tenant
    // that changed after the start-up pass is not left without it.
    const instance = await this.managedDb.findInstanceById(tenant.instance_id);
    if (instance?.provider === 'local') {
      await this.isolateTenant(instance, tenant);
    }

    if (tenant.desired_class) {
      this.logger.log(`[managed-db-reconciler] Scaling tenant ${tenant.id} to ${tenant.desired_class}`);
    }
    await this.completeOperation(tenant.id, token, 'ready', {
      desiredClass: null,
    });
  }

  private async handleRotating(
    tenant: { id: string; instance_id: string; db_name: string; db_user: string; provider_tenant_id: string | null },
    token: string,
  ): Promise<void> {
    this.logger.log(`[managed-db-reconciler] Rotating credentials for tenant ${tenant.id}`);

    if (tenant.provider_tenant_id?.startsWith('local:')) {
      const instance = await this.managedDb.findInstanceById(tenant.instance_id);
      if (instance) {
        const newPassword = crypto.randomBytes(16).toString('hex');
        const adminSql = this.connectToInstance(instance);
        try {
          await adminSql.unsafe(`ALTER ROLE "${tenant.db_user}" WITH PASSWORD '${newPassword}'`);
          const connectionUrl = this.buildTenantConnectionUrl(instance, tenant, newPassword);
          await this.rotateLocalTenantRoles(adminSql, instance, tenant);
          await this.completeOperation(tenant.id, token, 'ready', {
            credentialSecretRef: connectionUrl,
          });
          this.logger.log(`[managed-db-reconciler] Rotated credentials for local tenant ${tenant.id}`);
          return;
        } finally {
          await adminSql.end();
        }
      }
    }

    await this.completeOperation(tenant.id, token, 'ready');
  }

  private async handleDeleting(
    tenant: {
      id: string;
      instance_id: string;
      db_name: string;
      db_user: string;
      provider_tenant_id: string | null;
      credential_secret_ref: string | null;
      snapshot_on_delete: boolean | null;
      org_id: string;
      project_id: string;
      env_id: string | null;
      class: string;
      backup_retention: string | null;
    },
    token: string,
  ): Promise<void> {
    this.logger.log(`[managed-db-reconciler] Deleting tenant ${tenant.id}`);

    // Snapshot-on-delete: create a safety snapshot before destroying
    if (this.resolveTenantSnapshotSetting(tenant.snapshot_on_delete, tenant.class) && tenant.credential_secret_ref) {
      try {
        this.logger.log(`[managed-db-reconciler] Creating pre-delete snapshot for ${tenant.id}`);
        const [org, project, environment] = await Promise.all([
          this.orgs.findById(tenant.org_id),
          this.projects.findById(tenant.project_id),
          tenant.env_id ? this.environments.findById(tenant.env_id) : Promise.resolve(null),
        ]);

        await this.createPreDeleteSnapshot({
          ...tenant,
          credential_secret_ref: tenant.credential_secret_ref,
          org_slug: org?.slug ?? tenant.org_id,
          project_slug: project?.slug ?? tenant.project_id,
          env_name: environment?.name ?? tenant.env_id ?? 'deleted-env',
        });
      } catch (err) {
        // A snapshot was asked for: keep the database until one exists. The
        // drop is retried (see reconcileTenant) and parks at failed after a
        // day, with the database still in place.
        throw new ManagedDbProvisioningError(
          'snapshot_failed',
          `Pre-delete snapshot failed, so the database was kept: ${err instanceof Error ? err.message : String(err)}`,
        );
      }
    }

    // On a local instance the drop does not wait for a provider id: a tenant
    // deleted while it was being provisioned has a database but none yet.
    const instance = await this.managedDb.findInstanceById(tenant.instance_id);
    if (instance && (instance.provider === 'local' || tenant.provider_tenant_id?.startsWith('local:'))) {
      await this.deleteLocalDb(instance, tenant);
    }

    await this.managedDb.markTenantDeleted(tenant.id);
    this.logger.log(`[managed-db-reconciler] Tenant ${tenant.id} deleted`);
  }

  private async createPreDeleteSnapshot(tenant: {
    id: string;
    instance_id: string;
    org_id: string;
    project_id: string;
    env_id: string | null;
    class: string;
    backup_retention: string | null;
    org_slug: string;
    project_slug: string;
    env_name: string;
    credential_secret_ref: string;
  }): Promise<void> {
    const snapshotStorage = createSnapshotStorageClient();
    if (!snapshotStorage) {
      throw new Error('snapshot storage is not configured (EVE_DB_SNAPSHOT_BUCKET)');
    }
    const snapshotId = generateManagedDbSnapshotId();
    const retention = resolveManagedDbSnapshotRetention(undefined, {
      dbClass: tenant.class,
      tenantRetention: tenant.backup_retention,
    });
    const s3Key = buildSnapshotS3Key(
      tenant.org_slug,
      tenant.project_slug,
      tenant.env_name,
      snapshotId,
    );

    await this.snapshots.createSnapshot({
      id: snapshotId,
      tenant_id: tenant.id,
      org_id: tenant.org_id,
      project_id: tenant.project_id,
      env_id: tenant.env_id,
      instance_id: tenant.instance_id,
      created_by: 'system:pre-delete',
      trigger: 'pre_delete',
      s3_bucket: snapshotStorage.bucket,
      s3_key: s3Key,
      retention,
      expires_at: snapshotRetentionToExpiresAt(retention),
    });

    // Parse connection URL
    const url = new URL(tenant.credential_secret_ref);
    const dbConfig = {
      host: url.hostname,
      port: parseInt(url.port, 10) || 5432,
      username: decodeURIComponent(url.username),
      password: decodeURIComponent(url.password),
      database: url.pathname.replace(/^\//, ''),
    };

    // Execute synchronously (block deletion until snapshot completes, with 5 min timeout)
    try {
      const result = await executeSnapshot(dbConfig, { client: snapshotStorage.client, bucket: snapshotStorage.bucket, key: s3Key }, { timeoutMs: 5 * 60 * 1000 });
      await this.snapshots.completeSnapshot(snapshotId, {
        size_bytes: result.sizeBytes,
        db_size_bytes: result.dbSizeBytes,
        pg_version: result.pgVersion,
      });
      this.logger.log(`[managed-db-reconciler] Pre-delete snapshot ${snapshotId} completed (${result.sizeBytes} bytes)`);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      await this.snapshots.failSnapshot(snapshotId, message);
      throw err; // Re-throw so caller can handle
    }
  }

  private resolveTenantSnapshotSetting(configured: boolean | null, dbClass: string): boolean {
    if (configured !== null) {
      return configured;
    }
    return dbClass === 'db.p2' || dbClass === 'db.p3';
  }

  // ---------------------------------------------------------------------------
  // Local Postgres provider
  // ---------------------------------------------------------------------------

  /**
   * Connect to the system Postgres as admin (using DATABASE_URL).
   * Returns a short-lived sql connection for admin DDL operations.
   *
   * This connection and connectToTenantDb's are Eve's platform login on
   * databases tenants can reach (a tenant owns its own database), so both
   * pin search_path to pg_catalog at startup; statements on them name
   * catalog objects, and the schemas they create in, in full.
   */
  private connectToInstance(instance: { host: string; port: number }): Db {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error('DATABASE_URL not set — cannot connect for local managed DB provisioning');
    }
    // Parse admin credentials from DATABASE_URL, override host/port from instance.
    // sslmode is inherited from DATABASE_URL — both connect to the same Postgres.
    const url = new URL(databaseUrl);
    url.hostname = instance.host;
    url.port = String(instance.port);
    url.pathname = '/postgres';
    return createPinnedSearchPathDb(url.toString());
  }

  /** The platform login on the tenant's own database (see connectToInstance). */
  private connectToTenantDb(
    instance: { host: string; port: number },
    tenant: { db_name: string },
  ): Db {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error('DATABASE_URL not set — cannot connect for managed DB extension provisioning');
    }
    const url = new URL(databaseUrl);
    url.hostname = instance.host;
    url.port = String(instance.port);
    url.pathname = `/${tenant.db_name}`;
    return createPinnedSearchPathDb(url.toString());
  }

  private getMissingExtensions(
    desiredExtensions: string[] | null | undefined,
    enabledExtensions: string[] | null | undefined,
  ): SupportedExtension[] {
    const desired = normalizeManagedDbExtensions(desiredExtensions, {
      includeDisabledProviderGated: true,
    });
    const enabled = new Set(enabledExtensions ?? []);
    return desired.filter((extension) => !enabled.has(extension));
  }

  private mergeEnabledExtensions(
    currentExtensions: string[] | null | undefined,
    installedExtensions: SupportedExtension[],
  ): SupportedExtension[] {
    const current = (currentExtensions ?? []).filter(isSupportedExtensionName);
    return normalizeManagedDbExtensions([...current, ...installedExtensions], {
      includeDisabledProviderGated: true,
    });
  }

  private async installTenantExtensions(
    instance: {
      id: string;
      provider: string;
      provider_instance_id: string;
      engine_version: string;
      host: string;
      port: number;
    },
    tenant: { id: string; db_name: string; db_user: string },
    requestedExtensions: SupportedExtension[],
  ): Promise<void> {
    const needsTenantConnection = requestedExtensions.some(
      (extension) => getSupportedExtensionDefinition(extension).installScope === 'tenant_db',
    );
    const needsInstanceConnection = requestedExtensions.some(
      (extension) => getSupportedExtensionDefinition(extension).installScope === 'instance_admin_db',
    );
    const tenantSql = needsTenantConnection ? this.connectToTenantDb(instance, tenant) : null;
    const instanceSql = needsInstanceConnection ? this.connectToInstance(instance) : null;

    try {
      for (const extension of requestedExtensions) {
        const definition = getSupportedExtensionDefinition(extension);
        if (definition.mode === 'preload' && !isManagedDbExtensionEnabled(extension)) {
          throw new ManagedDbProvisioningError(
            'provider_unsupported',
            `Managed DB extension "${extension}" is provider-gated. Configure provider support and set ` +
            `${MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV}=${extension} on the API, worker, and orchestrator.`,
          );
        }

        const sql = definition.installScope === 'instance_admin_db' ? instanceSql : tenantSql;
        if (!sql) {
          throw new ManagedDbProvisioningError(
            'extension_install_failed',
            `No admin connection available for managed DB extension "${extension}" install scope "${definition.installScope}"`,
          );
        }

        const [available] = await sql<{ name: string }[]>`
          SELECT name
          FROM pg_catalog.pg_available_extensions
          WHERE name = ${definition.extname}
        `;
        if (!available) {
          throw new ManagedDbProvisioningError(
            'extension_unavailable',
            `Managed DB extension "${extension}" (Postgres extname "${definition.extname}") ` +
            `is not available on instance ${instance.id} ` +
            `(${instance.provider}/${instance.provider_instance_id}, engine ${instance.engine_version})`,
          );
        }

        if (definition.mode === 'preload') {
          const [preloadSetting] = await sql<{ setting: string }[]>`
            SELECT setting
            FROM pg_catalog.pg_settings
            WHERE name = 'shared_preload_libraries'
          `;
          if (!sharedPreloadLibrariesContains(preloadSetting?.setting, definition.preloadName)) {
            throw new ManagedDbProvisioningError(
              'preload_missing',
              `Managed DB extension "${extension}" requires shared_preload_libraries to include ` +
              `"${definition.preloadName}" on instance ${instance.id} ` +
              `(${instance.provider}/${instance.provider_instance_id}). Configure the Terraform-managed ` +
              `RDS parameter group in the deployment instance repo, reboot/restart the backing DB, ` +
              `then re-run deploy.`,
            );
          }
        }

        // A tenant database's extensions go into "public", by name (the
        // pinned search_path would otherwise choose pg_catalog). An
        // instance-scope extension (pg_cron) takes its control file's schema.
        const schemaClause = definition.installScope === 'tenant_db' ? ' SCHEMA "public"' : '';
        try {
          await sql.unsafe(
            `CREATE EXTENSION IF NOT EXISTS ${quotePostgresIdentifier(definition.extname)}${schemaClause}`,
          );
        } catch (err) {
          throw new ManagedDbProvisioningError(
            'extension_install_failed',
            `Failed to install managed DB extension "${extension}" on tenant ${tenant.id}: ` +
            `${err instanceof Error ? err.message : String(err)}`,
          );
        }

        const [schema] = await sql<{ schema_name: string }[]>`
          SELECT n.nspname AS schema_name
          FROM pg_catalog.pg_extension e
          JOIN pg_catalog.pg_namespace n ON n.oid = e.extnamespace
          WHERE e.extname = ${definition.extname}
        `;
        if (schema && !['public', 'pg_catalog', 'information_schema'].includes(schema.schema_name)) {
          await sql.unsafe(
            `GRANT USAGE ON SCHEMA ${quotePostgresIdentifier(schema.schema_name)} ` +
            `TO ${quotePostgresIdentifier(tenant.db_user)}`,
          );
        }
      }
    } finally {
      await tenantSql?.end();
      await instanceSql?.end();
    }
  }

  private buildTenantConnectionUrl(
    instance: { host: string; port: number },
    tenant: { db_name: string; db_user: string },
    password: string,
  ): string {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      throw new Error('DATABASE_URL not set — cannot build managed DB connection URL');
    }

    // Inherit sslmode (and any other query params) from DATABASE_URL.
    // The tenant connects to the same Postgres instance as the platform.
    const url = new URL(databaseUrl);
    url.username = tenant.db_user;
    url.password = password;
    url.hostname = instance.host;
    url.port = String(instance.port);
    url.pathname = `/${tenant.db_name}`;

    return url.toString();
  }

  /**
   * Create a real Postgres database and role on the local system Postgres.
   * Idempotent: will not fail if the role/database already exists.
   */
  private async provisionLocalDb(
    instance: { host: string; port: number },
    tenant: { db_name: string; db_user: string; class: string },
  ): Promise<string> {
    const password = crypto.randomBytes(16).toString('hex');
    const adminSql = this.connectToInstance(instance);

    try {
      // Create role (idempotent)
      const [existingRole] = await adminSql`
        SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = ${tenant.db_user}
      `;
      if (!existingRole) {
        await adminSql.unsafe(
          `CREATE ROLE "${tenant.db_user}" WITH LOGIN PASSWORD '${password}'`,
        );
      } else {
        // Role exists — update password so we always have a working credential
        await adminSql.unsafe(
          `ALTER ROLE "${tenant.db_user}" WITH PASSWORD '${password}'`,
        );
      }

      // PG 15+ no longer grants implicit membership when CREATEROLE creates a role.
      // We need membership to set the role as database OWNER.
      await adminSql.unsafe(
        `GRANT "${tenant.db_user}" TO CURRENT_USER`,
      );

      // Create database (idempotent)
      const [existingDb] = await adminSql`
        SELECT 1 FROM pg_catalog.pg_database WHERE datname = ${tenant.db_name}
      `;
      if (!existingDb) {
        await adminSql.unsafe(
          `CREATE DATABASE "${tenant.db_name}" OWNER "${tenant.db_user}"`,
        );
      }

      await this.isolateLocalTenantDb(adminSql, tenant, []);

      return this.buildTenantConnectionUrl(instance, tenant, password);
    } finally {
      await adminSql.end();
    }
  }

  /**
   * Drop database and role for a local tenant.
   * Terminates existing connections before dropping.
   */
  private async deleteLocalDb(
    instance: { host: string; port: number },
    tenant: { id: string; db_name: string; db_user: string },
  ): Promise<void> {
    const adminSql = this.connectToInstance(instance);

    try {
      // Terminate connections to the database
      await adminSql`
        SELECT pg_catalog.pg_terminate_backend(pid)
        FROM pg_catalog.pg_stat_activity
        WHERE datname = ${tenant.db_name} AND pid != pg_catalog.pg_backend_pid()
      `;

      await adminSql.unsafe(`DROP DATABASE IF EXISTS "${tenant.db_name}"`);
      await adminSql.unsafe(`DROP ROLE IF EXISTS "${tenant.db_user}"`);

      // Declared role logins only ever held privileges inside the tenant
      // database, so once it is gone they can be dropped outright.
      const roles = await this.managedDb.listTenantRoles(tenant.id);
      for (const role of roles) {
        await adminSql.unsafe(`DROP ROLE IF EXISTS ${quotePostgresIdentifier(role.db_user)}`);
      }
      if (roles.length > 0) {
        await this.managedDb.deleteTenantRoles(tenant.id);
      }
    } finally {
      await adminSql.end();
    }
  }

  // ---------------------------------------------------------------------------
  // Declared tenant roles (local provider)
  // ---------------------------------------------------------------------------

  private async planTenantRoleChanges(
    tenant: { id: string; desired_roles: ManagedDbRoleDeclaration[] },
  ): Promise<TenantRolePlan> {
    const desired = normalizeManagedDbRoles(tenant.desired_roles);
    const provisioned = await this.managedDb.listTenantRoles(tenant.id);
    return { desired, diff: diffManagedDbRoles(desired, provisioned), provisioned };
  }

  private describeRolePlan(diff: ManagedDbRoleDiff<ManagedDbTenantRole>): string {
    const parts: string[] = [];
    if (diff.create.length > 0) parts.push(`create ${diff.create.map((role) => role.name).join(', ')}`);
    if (diff.regrant.length > 0) parts.push(`regrant ${diff.regrant.map((role) => role.name).join(', ')}`);
    if (diff.drop.length > 0) parts.push(`drop ${diff.drop.map((role) => role.name).join(', ')}`);
    return parts.join('; ');
  }

  /**
   * Bring the tenant's Postgres login roles in line with the manifest:
   * drop roles that are no longer declared (a schema-owner role hands its
   * schema back first), re-grant roles whose grant set changed, then create
   * newly declared roles with fresh credentials. Then each schema-owner role
   * is given its schema (created, or handed over from the tenant owner) on
   * every run. A schema another role holds, or one holding objects a
   * hand-over does not move, fails the tenant before anything changes. No-op (and no connections opened) when nothing changed and no
   * role owns a schema.
   */
  private async applyLocalTenantRoleChanges(
    instance: { host: string; port: number },
    tenant: { id: string; db_name: string; db_user: string; class: string },
    plan: TenantRolePlan,
  ): Promise<void> {
    const { desired, diff, provisioned } = plan;
    if (!hasManagedDbRoleChanges(diff) && !ownsSchemas(desired)) return;

    const adminSql = this.connectToInstance(instance);
    const tenantSql = this.connectToTenantDb(instance, tenant);

    try {
      // Owner roles dropped in this run hand their schema back before any
      // claim, so their schema counts as the tenant owner's.
      const releasing = diff.drop.filter((role) => managedDbRoleOwnedSchema(role) !== null).map((role) => role.db_user);
      for (const role of desired) {
        const target = this.schemaTarget(tenant, role);
        if (target) await this.withSchemaConflict(() => checkManagedDbSchemaClaim(tenantSql, target, { releasing }));
      }

      for (const role of diff.drop) {
        if (managedDbRoleOwnedSchema(role) !== null) {
          await this.dropLocalSchemaOwnerRole(adminSql, tenantSql, tenant, role);
        } else {
          await this.dropLocalTenantRole(adminSql, tenantSql, tenant, role);
        }
      }

      for (const role of diff.regrant) {
        const existing = provisioned.find((candidate) => candidate.name === role.name);
        if (!existing) continue;
        const revoke = buildManagedDbRoleRevokeSql({
          dbName: tenant.db_name,
          ownerUser: tenant.db_user,
          roleUser: existing.db_user,
        });
        for (const statement of revoke.tenant) {
          await tenantSql.unsafe(statement);
        }
        if (!isManagedDbRoleGrants(role.grants)) continue;
        await this.grantLocalTenantRole(adminSql, tenantSql, tenant, existing.db_user, role.grants);
        await this.managedDb.updateTenantRoleGrants(tenant.id, role.name, role.grants);
      }

      for (const role of diff.create) {
        const roleUser = generateManagedDbRoleUser(tenant.db_user, role.name);
        const password = crypto.randomBytes(16).toString('hex');
        const schema = managedDbRoleOwnedSchema(role);
        await this.ensureLocalRoleLogin(adminSql, roleUser, password, connectionLimitFor(tenant.class));
        if (schema !== null) {
          // CONNECT, and the platform login's membership (as for the owner
          // role), which it needs to give the schema and take it back.
          const sql = buildManagedDbSchemaOwnerSql({
            dbName: tenant.db_name,
            ownerUser: tenant.db_user,
            roleUser,
            schema,
          });
          for (const statement of sql.instance) {
            await adminSql.unsafe(statement);
          }
        } else if (isManagedDbRoleGrants(role.grants)) {
          await this.grantLocalTenantRole(adminSql, tenantSql, tenant, roleUser, role.grants);
        }
        await this.managedDb.upsertTenantRole({
          id: generateManagedDbTenantRoleId(),
          tenant_id: tenant.id,
          name: role.name,
          grants: schema !== null ? MANAGED_DB_SCHEMA_OWNER_GRANTS : String(role.grants),
          schema_name: schema,
          db_user: roleUser,
          credential_secret_ref: this.buildTenantConnectionUrl(
            instance,
            { db_name: tenant.db_name, db_user: roleUser },
            password,
          ),
        });
      }

      for (const role of desired) {
        const target = this.schemaTarget(tenant, role);
        if (!target) continue;
        // The tenant's other logins get nothing in the schema, except the
        // owner's read access for snapshots.
        const others = [tenant.db_user, ...desired
          .filter((other) => other.name !== role.name)
          .map((other) => generateManagedDbRoleUser(tenant.db_user, other.name))];
        const claim = await this.withSchemaConflict(() => claimManagedDbSchema(tenantSql, target, { revokeFrom: others }));
        if (claim.action === 'created') {
          this.logger.log(`[managed-db-reconciler] Created schema ${target.schema} of tenant ${tenant.id} for ${role.name}`);
        } else if (claim.action === 'handed_over') {
          const moved = Object.entries(claim.objects)
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([kind, count]) => `${count} ${kind}`)
            .join(', ');
          this.logger.log(
            `[managed-db-reconciler] Handed schema ${target.schema} of tenant ${tenant.id} to ${role.name}: ${moved || 'no objects'}`,
          );
        }
      }
    } finally {
      await tenantSql.end();
      await adminSql.end();
    }
  }

  /** The schema a declared role owns, as the helpers name it; null for `public` data roles. */
  private schemaTarget(
    tenant: { db_name: string; db_user: string },
    role: ManagedDbRoleDeclaration,
  ): ManagedDbSchemaTarget | null {
    const schema = managedDbRoleOwnedSchema(role);
    if (schema === null) return null;
    return {
      dbName: tenant.db_name,
      schema,
      roleUser: generateManagedDbRoleUser(tenant.db_user, role.name),
      ownerUser: tenant.db_user,
    };
  }

  /** A schema another role holds fails the tenant with schema_owner_conflict. */
  private async withSchemaConflict<T>(work: () => Promise<T>): Promise<T> {
    try {
      return await work();
    } catch (err) {
      if (err instanceof ManagedDbSchemaConflictError) {
        throw new ManagedDbProvisioningError(err.code, err.message);
      }
      throw err;
    }
  }

  /**
   * Drop a schema-owner role: the login stops signing in and its sessions
   * end, its schema and everything else it owns in the tenant database go
   * back to the tenant owner and its privileges there are revoked (one
   * transaction), then the login goes.
   */
  private async dropLocalSchemaOwnerRole(
    adminSql: Db,
    tenantSql: Db,
    tenant: { id: string; db_name: string; db_user: string },
    role: ManagedDbTenantRole,
  ): Promise<void> {
    const schema = managedDbRoleOwnedSchema(role);
    if (schema !== null) {
      await releaseManagedDbSchema(tenantSql, {
        dbName: tenant.db_name,
        schema,
        roleUser: role.db_user,
        ownerUser: tenant.db_user,
      });
      this.logger.log(`[managed-db-reconciler] Handed schema ${schema} of tenant ${tenant.id} back from ${role.name}`);
    }
    // The hand-back already ended the login's sessions and refuses new ones.
    await adminSql.unsafe(`DROP ROLE IF EXISTS ${quotePostgresIdentifier(role.db_user)}`);
    await this.managedDb.deleteTenantRole(tenant.id, role.name);
  }

  /**
   * Create (or reset) a least-privilege login role. Idempotent so a retry
   * after a partial failure converges instead of erroring on "already exists".
   */
  private async ensureLocalRoleLogin(
    adminSql: Db,
    roleUser: string,
    password: string,
    connectionLimit: number | null,
  ): Promise<void> {
    const [existingRole] = await adminSql`
      SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = ${roleUser}
    `;
    if (existingRole) {
      await adminSql.unsafe(
        `ALTER ROLE ${quotePostgresIdentifier(roleUser)} WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '${password}'`,
      );
      if (connectionLimit) await this.applyConnectionLimit(adminSql, roleUser, connectionLimit);
      return;
    }
    const limit = connectionLimit ? ` CONNECTION LIMIT ${connectionLimit}` : '';
    await adminSql.unsafe(
      `CREATE ROLE ${quotePostgresIdentifier(roleUser)} WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT${limit} PASSWORD '${password}'`,
    );
  }

  // ---------------------------------------------------------------------------
  // Tenant isolation (local provider)
  // ---------------------------------------------------------------------------

  /**
   * A tenant database accepts only its own logins: the owner (by ownership)
   * and declared roles (granted CONNECT explicitly). Each login gets its
   * class's per-login limit unless one is already set. The database's limit
   * counts every login, Eve's own included, so it is the class maximum plus
   * the platform reserve (managedDbDatabaseConnectionLimit), set only when
   * there is none: a limit an operator set is theirs. Idempotent.
   */
  private async isolateLocalTenantDb(
    adminSql: Db,
    tenant: { db_name: string; db_user: string; class: string },
    roleUsers: string[],
  ): Promise<void> {
    await adminSql.unsafe(`REVOKE CONNECT ON DATABASE ${quotePostgresIdentifier(tenant.db_name)} FROM PUBLIC`);
    const limits = getManagedDbLimits(tenant.class);
    if (!limits) return;
    await this.applyDatabaseConnectionLimit(adminSql, tenant.db_name, managedDbDatabaseConnectionLimit(limits));
    for (const login of [tenant.db_user, ...roleUsers]) {
      await this.applyConnectionLimit(adminSql, login, limits.connectionLimitSql);
    }
  }

  /** Sets a database's connection limit only when it has none (-1); a limit already set is the operator's. */
  private async applyDatabaseConnectionLimit(adminSql: Db, dbName: string, limit: number): Promise<void> {
    const [row] = await adminSql`
      SELECT datconnlimit FROM pg_catalog.pg_database WHERE datname = ${dbName}
    `;
    if (!row) return;
    const current = Number((row as { datconnlimit: unknown }).datconnlimit);
    if (current !== -1) return;
    await adminSql.unsafe(`ALTER DATABASE ${quotePostgresIdentifier(dbName)} CONNECTION LIMIT ${limit}`);
    this.logger.log(`[managed-db-reconciler] Set connection limit ${limit} on database ${dbName}`);
  }

  /** Sets a login's connection limit only when it has none (-1). */
  private async applyConnectionLimit(adminSql: Db, login: string, limit: number): Promise<void> {
    const [row] = await adminSql`
      SELECT rolconnlimit FROM pg_catalog.pg_roles WHERE rolname = ${login}
    `;
    if (!row || Number((row as { rolconnlimit: unknown }).rolconnlimit) !== -1) return;
    await adminSql.unsafe(`ALTER ROLE ${quotePostgresIdentifier(login)} CONNECTION LIMIT ${limit}`);
    this.logger.log(`[managed-db-reconciler] Set connection limit ${limit} on ${login}`);
  }

  /** Isolates one tenant (with its declared roles) on a local instance. */
  private async isolateTenant(
    instance: { host: string; port: number },
    tenant: { id: string; db_name: string; db_user: string; class: string },
  ): Promise<void> {
    const adminSql = this.connectToInstance(instance);
    try {
      const roles = await this.managedDb.listTenantRoles(tenant.id);
      await this.isolateLocalTenantDb(adminSql, tenant, roles.map((role) => role.db_user));
    } finally {
      await adminSql.end();
    }
  }

  /** One pass over every ready tenant on a local instance (start-up). */
  private async isolateReadyTenants(): Promise<void> {
    const instances = await this.managedDb.listInstances();
    for (const instance of instances) {
      if (instance.provider !== 'local') continue;
      const tenants = (await this.managedDb.listTenantsByInstance(instance.id))
        .filter((tenant) => tenant.status === 'ready' && !tenant.deleted_at);
      if (tenants.length === 0) continue;
      const adminSql = this.connectToInstance(instance);
      try {
        for (const tenant of tenants) {
          try {
            const roles = await this.managedDb.listTenantRoles(tenant.id);
            await this.isolateLocalTenantDb(adminSql, tenant, roles.map((role) => role.db_user));
          } catch (err) {
            this.logger.error(
              `[managed-db-reconciler] Could not isolate tenant ${tenant.id}: ${err instanceof Error ? err.message : String(err)}`,
            );
          }
        }
        this.logger.log(`[managed-db-reconciler] Isolation pass: ${tenants.length} tenant(s) on ${instance.id}`);
      } finally {
        await adminSql.end();
      }
    }
  }

  private async grantLocalTenantRole(
    adminSql: Db,
    tenantSql: Db,
    tenant: { db_name: string; db_user: string },
    roleUser: string,
    grants: ManagedDbRoleGrants,
  ): Promise<void> {
    const sql = buildManagedDbRoleGrantSql({
      dbName: tenant.db_name,
      ownerUser: tenant.db_user,
      roleUser,
      grants,
    });
    for (const statement of sql.instance) {
      await adminSql.unsafe(statement);
    }
    for (const statement of sql.tenant) {
      await tenantSql.unsafe(statement);
    }
  }

  private async dropLocalTenantRole(
    adminSql: Db,
    tenantSql: Db,
    tenant: { id: string; db_name: string; db_user: string },
    role: ManagedDbTenantRole,
  ): Promise<void> {
    const revoke = buildManagedDbRoleRevokeSql({
      dbName: tenant.db_name,
      ownerUser: tenant.db_user,
      roleUser: role.db_user,
    });
    for (const statement of revoke.tenant) {
      await tenantSql.unsafe(statement);
    }
    for (const statement of revoke.instance) {
      await adminSql.unsafe(statement);
    }
    await adminSql`
      SELECT pg_catalog.pg_terminate_backend(pid)
      FROM pg_catalog.pg_stat_activity
      WHERE usename = ${role.db_user} AND pid != pg_catalog.pg_backend_pid()
    `;
    await adminSql.unsafe(`DROP ROLE IF EXISTS ${quotePostgresIdentifier(role.db_user)}`);
    await this.managedDb.deleteTenantRole(tenant.id, role.name);
  }

  /** Rotate every declared role's password alongside the owner credential. */
  private async rotateLocalTenantRoles(
    adminSql: Db,
    instance: { host: string; port: number },
    tenant: { id: string; db_name: string },
  ): Promise<void> {
    const roles = await this.managedDb.listTenantRoles(tenant.id);
    for (const role of roles) {
      const password = crypto.randomBytes(16).toString('hex');
      await adminSql.unsafe(
        `ALTER ROLE ${quotePostgresIdentifier(role.db_user)} WITH PASSWORD '${password}'`,
      );
      await this.managedDb.updateTenantRoleCredentialSecretRef(
        tenant.id,
        role.name,
        this.buildTenantConnectionUrl(instance, { db_name: tenant.db_name, db_user: role.db_user }, password),
      );
    }
  }

  /**
   * Register the system Postgres as a local managed DB instance.
   * Idempotent — checks for existing instance with provider='local' first.
   */
  private async seedLocalInstance(): Promise<void> {
    const databaseUrl = process.env.DATABASE_URL;
    if (!databaseUrl) {
      this.logger.warn('[managed-db-reconciler] Cannot seed local instance: DATABASE_URL not set');
      return;
    }

    // One local instance row per class the operator offers (placement
    // matches the tenant's class to the row's), each seeded once.
    const classes = seedClasses();
    const instances = await this.managedDb.listInstances();
    const missing = classes.filter(
      (dbClass) => !instances.some((i) => i.provider === 'local' && i.instance_class === dbClass),
    );
    if (missing.length === 0) {
      this.logger.log(`[managed-db-reconciler] Local instances already exist for ${classes.join(', ')}`);
      return;
    }

    // Parse host/port from DATABASE_URL
    const url = new URL(databaseUrl);
    const host = url.hostname;
    const port = parseInt(url.port || '5432', 10);
    const engineVersion = await this.serverMajorVersion();

    for (const dbClass of missing) {
      const instance = await this.managedDb.createInstance({
        id: generateManagedDbInstanceId(),
        provider: 'local',
        provider_instance_id: dbClass === 'db.p1' ? 'local-system-postgres' : `local-system-postgres-${dbClass}`,
        region: 'local',
        engine: 'postgres',
        engine_version: engineVersion,
        host,
        port,
        instance_class: dbClass,
        capacity_json: { max_tenants: 50 },
      });
      this.logger.log(
        `[managed-db-reconciler] Seeded local managed DB instance ${instance.id} (${dbClass}, Postgres ${engineVersion}, ${host}:${port})`,
      );
    }
  }

  /** The platform server's major version, e.g. "15"; "16" if it cannot be read. */
  private async serverMajorVersion(): Promise<string> {
    try {
      const [row] = await this.db<{ server_version_num: string }[]>`
        SELECT current_setting('server_version_num') AS server_version_num
      `;
      const num = Number(row?.server_version_num);
      if (Number.isInteger(num) && num >= 100000) return String(Math.floor(num / 10000));
    } catch (err) {
      this.logger.warn(`[managed-db-reconciler] Could not read the server version: ${err instanceof Error ? err.message : String(err)}`);
    }
    return '16';
  }
}

/** Declared roles, and how the provisioned ones must change to match them. */
interface TenantRolePlan {
  desired: ManagedDbRoleDeclaration[];
  diff: ManagedDbRoleDiff<ManagedDbTenantRole>;
  provisioned: ManagedDbTenantRole[];
}

/**
 * At provisioning, owner roles already recorded are created again (login,
 * password, CONNECT, the platform login's membership): the database may be
 * new (a tenant revived after a destroy, or retried after a failure), and a
 * release before 0.1.330 can drop the database and leave such a record.
 */
function withOwnerRolesSetUpAgain(plan: TenantRolePlan): TenantRolePlan {
  const creating = new Set(plan.diff.create.map((role) => role.name));
  const again = plan.desired.filter((role) => managedDbRoleOwnedSchema(role) !== null && !creating.has(role.name));
  return again.length === 0 ? plan : { ...plan, diff: { ...plan.diff, create: [...plan.diff.create, ...again] } };
}

/** Whether any declared role owns a schema (checked on every run). */
function ownsSchemas(desired: ManagedDbRoleDeclaration[]): boolean {
  return desired.some((role) => managedDbRoleOwnedSchema(role) !== null);
}

/** The class's per-login connection limit, or null for an unknown class. */
function connectionLimitFor(dbClass: string): number | null {
  return getManagedDbLimits(dbClass)?.connectionLimitSql ?? null;
}

/** How long a failing drop is retried before the tenant parks at failed. */
const DROP_RETRY_WINDOW_MS = 24 * 60 * 60 * 1000;
const DROP_RETRY_MIN_WAIT_MS = 60 * 1000;
const DROP_RETRY_MAX_WAIT_MS = 60 * 60 * 1000;

/**
 * Whether a deleted tenant is due a drop attempt. After a failed one (its
 * error recorded, `updated_at` the time of the try) the next waits for a time
 * that doubles with the time since the delete: 1 minute in the first 2, then
 * 2, 4, 8... minutes, at most an hour. So a failing drop, and the snapshot it
 * may repeat, runs about 30 times in its day rather than every 30 seconds.
 */
function dropAttemptDue(
  tenant: { deleted_at?: Date | string | null; updated_at?: Date | string | null; last_error_code?: string | null },
  now = Date.now(),
): boolean {
  if (!tenant.last_error_code || !tenant.deleted_at || !tenant.updated_at) return true;
  const sinceDelete = now - new Date(tenant.deleted_at).getTime();
  const sinceTry = now - new Date(tenant.updated_at).getTime();
  if (!Number.isFinite(sinceDelete) || !Number.isFinite(sinceTry)) return true;
  let wait = DROP_RETRY_MIN_WAIT_MS;
  while (wait < DROP_RETRY_MAX_WAIT_MS && wait * 2 <= sinceDelete) wait *= 2;
  return sinceTry >= Math.min(wait, DROP_RETRY_MAX_WAIT_MS);
}

function withinDropRetryWindow(deletedAt: Date | string | null | undefined): boolean {
  if (!deletedAt) return false;
  const since = Date.now() - new Date(deletedAt).getTime();
  return Number.isFinite(since) && since < DROP_RETRY_WINDOW_MS;
}

/** Classes to seed local instances for: `EVE_MANAGED_DB_SEED_CLASSES`, known classes only (default db.p1). */
function seedClasses(): string[] {
  const configured = (process.env.EVE_MANAGED_DB_SEED_CLASSES ?? 'db.p1')
    .split(',')
    .map((value) => value.trim())
    .filter((value) => value && getManagedDbLimits(value));
  return configured.length > 0 ? [...new Set(configured)] : ['db.p1'];
}
