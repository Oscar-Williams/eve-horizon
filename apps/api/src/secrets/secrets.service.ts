import { Injectable, Inject, Logger, BadRequestException, NotFoundException, InternalServerErrorException, Optional } from '@nestjs/common';
import { randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import type { Db } from '@eve/db';
import {
  integrationQueries,
  oauthAppConfigQueries,
  orgQueries,
  projectManifestQueries,
  projectQueries,
  secretQueries,
  systemSettingsQueries,
  type SecretScopeType,
  type SecretType,
} from '@eve/db';
import { ManifestSchema, getManifestRequiredSecrets, generateSecretId, findClosestMatches, isUserSecretWithheldKey, type CreateSecretRequest, type SecretListResponse, type SecretMaskedResponse, type SecretResponse, type SecretStorageCounts, type SecretValidationResult, type SecretsReencryptResponse, type UpdateSecretRequest } from '@eve/shared';
import * as yaml from 'yaml';
import { SecurityService } from '../security/security.service.js';
import type { AuthUser } from '../auth/auth.types.js';
import { countStoredCredentials, legacyCredentialRows } from './credential-storage.js';
import {
  SECRETS_CIPHERTEXT_FORMAT_SETTING,
  SecretCipher,
  maskSecretValue,
  type SecretLocation,
} from './secret-cipher.js';

export { maskSecretValue } from './secret-cipher.js';

const SAFE_SECRET_ALLOWLIST = new Set(['GITHUB_WEBHOOK_SECRET']);
/** Project rule: under `strict`, secret values are write-only through the API. */
const VALUE_READ_RULE = 'secrets.value_read';
const REENCRYPT_BATCH = 200;

@Injectable()
export class SecretsService {
  private readonly logger = new Logger(SecretsService.name);
  private secrets: ReturnType<typeof secretQueries>;
  private projects: ReturnType<typeof projectQueries>;
  private orgs: ReturnType<typeof orgQueries>;
  private manifests: ReturnType<typeof projectManifestQueries>;
  private readonly cipher: SecretCipher;

  constructor(
    @Inject('DB') private readonly db: Db,
    @Optional() private readonly security?: SecurityService,
  ) {
    this.secrets = secretQueries(this.db);
    this.projects = projectQueries(this.db);
    this.orgs = orgQueries(this.db);
    this.manifests = projectManifestQueries(this.db);
    this.cipher = new SecretCipher(this.db, this.security);
  }

  async create(scopeType: SecretScopeType, scopeId: string, data: CreateSecretRequest): Promise<SecretResponse> {
    this.ensureConfigured();
    await this.ensureScopeExists(scopeType, scopeId);
    const encrypted = await this.encrypt(data.value, { scope_type: scopeType, scope_id: scopeId, key: data.key });
    const existing = await this.secrets.findByScopeAndKey(scopeType, scopeId, data.key);
    if (existing) {
      const updated = await this.secrets.updateByKey(scopeType, scopeId, data.key, {
        value_encrypted: encrypted,
        type: data.type ?? existing.type,
      });
      if (!updated) {
        throw new NotFoundException(`Secret ${data.key} not found`);
      }
      return this.toResponse(updated);
    }

    const id = generateSecretId();
    const secret = await this.secrets.create({
      id,
      scope_type: scopeType,
      scope_id: scopeId,
      key: data.key,
      type: data.type ?? 'env_var',
      value_encrypted: encrypted,
    });
    return this.toResponse(secret);
  }

  async list(
    scopeType: SecretScopeType,
    scopeId: string,
    options: { limit: number; offset: number },
  ): Promise<SecretListResponse> {
    await this.ensureScopeExists(scopeType, scopeId);
    const secrets = await this.secrets.listByScope(scopeType, scopeId, options);
    return {
      data: secrets.map((secret) => this.toResponse(secret)),
      pagination: {
        limit: options.limit,
        offset: options.offset,
        count: secrets.length,
      },
    };
  }

  async showMasked(scopeType: SecretScopeType, scopeId: string, key: string): Promise<SecretMaskedResponse> {
    this.ensureConfigured();
    await this.ensureScopeExists(scopeType, scopeId);
    const secret = await this.secrets.findByScopeAndKey(scopeType, scopeId, key);
    if (!secret) {
      throw new NotFoundException(`Secret ${key} not found`);
    }
    const location = { scope_type: scopeType, scope_id: scopeId, key };
    const decrypted = await this.decrypt(secret.value_encrypted, location);
    return {
      ...this.toResponse(secret),
      masked_value: maskSecretValue(decrypted),
      length: decrypted.length,
      fingerprint: this.cipher.fingerprint(location, decrypted),
    };
  }

  async update(
    scopeType: SecretScopeType,
    scopeId: string,
    key: string,
    updates: UpdateSecretRequest,
  ): Promise<SecretResponse> {
    this.ensureConfigured();
    await this.ensureScopeExists(scopeType, scopeId);
    if (!updates.value && !updates.type) {
      throw new BadRequestException('No updates provided');
    }
    const encrypted = updates.value
      ? await this.encrypt(updates.value, { scope_type: scopeType, scope_id: scopeId, key })
      : undefined;
    const updated = await this.secrets.updateByKey(scopeType, scopeId, key, {
      value_encrypted: encrypted,
      type: updates.type,
    });
    if (!updated) {
      throw new NotFoundException(`Secret ${key} not found`);
    }
    return this.toResponse(updated);
  }

  /**
   * Update a secret value only if it already exists. Returns true if updated, false if not found.
   * Used by the internal write-back endpoint — never creates new secrets.
   */
  async updateIfExists(scopeType: 'user' | 'org' | 'project' | 'system', scopeId: string, key: string, value: string): Promise<boolean> {
    this.ensureConfigured();
    const encrypted = await this.encrypt(value, { scope_type: scopeType, scope_id: scopeId, key });
    const updated = await this.secrets.updateByKey(scopeType as SecretScopeType, scopeId, key, { value_encrypted: encrypted });
    return updated !== null && updated !== undefined;
  }

  async delete(scopeType: SecretScopeType, scopeId: string, key: string): Promise<void> {
    await this.ensureScopeExists(scopeType, scopeId);
    const deleted = await this.secrets.deleteByKey(scopeType, scopeId, key);
    if (!deleted) {
      throw new NotFoundException(`Secret ${key} not found`);
    }
  }

  /**
   * Bootstrap system secrets from system-secrets.env.local file.
   * Loads KEY=VALUE pairs and upserts them into the secrets table with scope_type='system' and scope_id='system'.
   * @returns Number of secrets loaded
   */
  async loadSystemSecrets(): Promise<number> {
    this.ensureConfigured();

    // Determine project root (go up from apps/api)
    const projectRoot = join(__dirname, '..', '..', '..', '..');
    const systemSecretsPath = join(projectRoot, 'system-secrets.env.local');

    let fileContent: string;
    try {
      fileContent = readFileSync(systemSecretsPath, 'utf-8');
    } catch (error) {
      // File doesn't exist, return 0
      return 0;
    }

    const lines = fileContent.split('\n');
    let loadedCount = 0;

    for (const line of lines) {
      const trimmed = line.trim();

      // Skip empty lines and comments
      if (!trimmed || trimmed.startsWith('#')) {
        continue;
      }

      // Parse KEY=VALUE
      const equalIndex = trimmed.indexOf('=');
      if (equalIndex === -1) {
        continue; // Skip malformed lines
      }

      const key = trimmed.slice(0, equalIndex).trim();
      const value = trimmed.slice(equalIndex + 1).trim();

      if (!key) {
        continue; // Skip if key is empty
      }

      // Upsert the secret (create will update if exists)
      await this.create('system', 'system', {
        key,
        value,
        type: 'env_var',
      });

      loadedCount++;
    }

    console.log(`Loaded ${loadedCount} system secrets from ${systemSecretsPath}`);
    return loadedCount;
  }

  async resolveForOrg(orgId: string): Promise<Array<{ key: string; value: string; type: SecretType }>> {
    this.ensureConfigured();
    await this.ensureScopeExists('org', orgId);

    const resolved = new Map<string, { value: string; type: SecretType; scope_type: 'user' | 'org' | 'project' | 'system'; scope_id: string }>();

    // Resolution order: system → org (org wins)

    // 1. Load system secrets
    const systemSecrets = await this.secrets.listByScope('system', 'system', { limit: 500, offset: 0 });
    await this.decryptSecrets(systemSecrets, resolved, 'system', 'system');

    // 2. Layer org secrets on top (org overrides system)
    const orgSecrets = await this.secrets.listByScope('org', orgId, { limit: 500, offset: 0 });
    await this.decryptSecrets(orgSecrets, resolved, 'org', orgId);

    return Array.from(resolved.entries()).map(([key, entry]) => ({
      key,
      value: entry.value,
      type: entry.type,
    }));
  }

  async resolveForProject(projectId: string, userId?: string): Promise<Array<{ key: string; value: string; type: SecretType; scope_type: 'user' | 'org' | 'project' | 'system'; scope_id: string }>> {
    this.ensureConfigured();
    const project = await this.projects.findById(projectId, { include_deleted: false });
    if (!project) {
      throw new NotFoundException(`Project ${projectId} not found`);
    }

    const orgId = project.org_id;

    const resolved = new Map<string, { value: string; type: SecretType; scope_type: 'user' | 'org' | 'project' | 'system'; scope_id: string }>();

    // Resolution order: system → org → user → project (project wins)

    // 1. Load system secrets (overrides host env)
    const systemSecrets = await this.secrets.listByScope('system', 'system', { limit: 500, offset: 0 });
    await this.decryptSecrets(systemSecrets, resolved, 'system', 'system');

    // 2. Layer org secrets on top (org overrides system)
    const orgSecrets = await this.secrets.listByScope('org', orgId, { limit: 500, offset: 0 });
    await this.decryptSecrets(orgSecrets, resolved, 'org', orgId);

    // 3. Layer user secrets on top (user overrides org)
    if (userId) {
      const userSecrets = await this.secrets.listByScope('user', userId, { limit: 500, offset: 0 });
      await this.decryptSecrets(await this.withholdUserRoutingSecrets(projectId, userId, userSecrets), resolved, 'user', userId);
    }

    // 4. Layer project secrets on top (highest priority, project wins)
    const projectSecrets = await this.secrets.listByScope('project', projectId, { limit: 500, offset: 0 });
    await this.decryptSecrets(projectSecrets, resolved, 'project', projectId);

    return Array.from(resolved.entries()).map(([key, entry]) => ({
      key,
      value: entry.value,
      type: entry.type,
      scope_type: entry.scope_type,
      scope_id: entry.scope_id,
    }));
  }

  /**
   * A user's own secrets must not choose where model traffic goes, or load
   * code into the job, because the job also holds the project's and org's
   * provider keys. Under the project's `strict` profile such user secrets are
   * left out (a project or org secret of the same name then applies); under
   * `audit` they are kept and recorded. A user's own provider key is kept.
   */
  private async withholdUserRoutingSecrets<T extends { key: string }>(
    projectId: string,
    userId: string,
    userSecrets: T[],
  ): Promise<T[]> {
    const withheld = userSecrets.filter((secret) => isUserSecretWithheldKey(secret.key));
    if (withheld.length === 0 || !this.security) return userSecrets;
    const profile = await this.security.decide('harness.user_secret_routing', {
      projectId,
      governing: 'project',
      actor: { user_id: userId } as AuthUser,
      detail: { secrets: withheld.map((secret) => secret.key).sort().join(',') },
    });
    if (profile !== 'strict') return userSecrets;
    return userSecrets.filter((secret) => !isUserSecretWithheldKey(secret.key));
  }

  async validateRequiredSecrets(projectId: string, requiredKeys: string[], userId?: string): Promise<SecretValidationResult> {
    const project = await this.projects.findById(projectId, { include_deleted: false });
    if (!project) {
      throw new NotFoundException(`Project ${projectId} not found`);
    }

    const required = Array.from(new Set(requiredKeys.filter((key) => key && typeof key === 'string')));
    if (required.length === 0) {
      return { missing: [] };
    }

    const available = await this.listAvailableSecretKeys(projectId, userId);
    const missing = required.filter((key) => !available.has(key));
    const hints = (key: string): string[] => [
      `eve secrets set ${key} <value> --project ${projectId}`,
      `eve secrets set ${key} <value> --org ${project.org_id}`,
      'eve secrets set ' + key + ' <value> --system',
    ];

    return {
      missing: missing.map((key) => {
        const closest = findClosestMatches(key, available, 2);
        const suggestion = closest.length > 0 ? `Did you mean "${closest[0]}"?` : undefined;
        return { key, hints: hints(key), suggestion };
      }),
    };
  }

  async validateManifestSecrets(projectId: string, manifestYaml: string): Promise<SecretValidationResult> {
    const parsed = yaml.parse(manifestYaml);
    const validated = ManifestSchema.safeParse(parsed);
    if (!validated.success) {
      throw new BadRequestException(`Invalid YAML: ${validated.error.message}`);
    }
    const required = getManifestRequiredSecrets(validated.data);
    return this.validateRequiredSecrets(projectId, required);
  }

  async validateLatestManifestSecrets(projectId: string): Promise<SecretValidationResult> {
    const manifest = await this.manifests.findLatestByProject(projectId);
    if (!manifest) {
      throw new BadRequestException(`No manifest found for project ${projectId}`);
    }
    return this.validateManifestSecrets(projectId, manifest.manifest_yaml);
  }

  async resolveProjectSecretValue(projectId: string, key: string): Promise<string | null> {
    if (!this.cipher.configured) {
      return null;
    }
    await this.ensureScopeExists('project', projectId);
    const secret = await this.secrets.findByScopeAndKey('project', projectId, key);
    if (!secret) {
      return null;
    }
    return this.decrypt(secret.value_encrypted, { scope_type: 'project', scope_id: projectId, key });
  }

  /**
   * Create the safe secrets that are missing, with generated values. The
   * values made here are returned once, in this response: under a project's
   * strict profile (`secrets.value_read`) it is the only way to see them.
   */
  async ensureSafeSecrets(
    projectId: string,
    keys: string[],
  ): Promise<{ created: string[]; existing: string[]; values: Array<{ key: string; value: string }> }> {
    this.ensureConfigured();
    await this.ensureScopeExists('project', projectId);

    const unique = Array.from(new Set(keys));
    for (const key of unique) {
      if (!SAFE_SECRET_ALLOWLIST.has(key)) {
        throw new BadRequestException(`Secret ${key} is not allowed for ensure/export`);
      }
    }

    const created: string[] = [];
    const existing: string[] = [];
    const values: Array<{ key: string; value: string }> = [];

    for (const key of unique) {
      const current = await this.secrets.findByScopeAndKey('project', projectId, key);
      if (current) {
        existing.push(key);
        continue;
      }
      const value = randomBytes(32).toString('base64url');
      await this.create('project', projectId, { key, value, type: 'env_var' });
      created.push(key);
      values.push({ key, value });
    }

    return { created, existing, values };
  }

  /**
   * Return the values of safe secrets. Under the project's strict profile
   * (`secrets.value_read`) values are write-only: 403. Under `audit` the
   * read is recorded.
   */
  async exportSafeSecrets(
    projectId: string,
    keys: string[],
    actor?: AuthUser | null,
  ): Promise<Array<{ key: string; value: string }>> {
    this.ensureConfigured();
    await this.ensureScopeExists('project', projectId);

    const unique = Array.from(new Set(keys));
    for (const key of unique) {
      if (!SAFE_SECRET_ALLOWLIST.has(key)) {
        throw new BadRequestException(`Secret ${key} is not allowed for export`);
      }
    }

    await this.security?.gate(
      VALUE_READ_RULE,
      { projectId, governing: 'project', actor, detail: { keys: unique.join(',') } },
      "Secret values are write-only under this project's security profile; ensure returns a generated value once",
    );

    const exports: Array<{ key: string; value: string }> = [];
    for (const key of unique) {
      const secret = await this.secrets.findByScopeAndKey('project', projectId, key);
      if (!secret) {
        throw new NotFoundException(`Secret ${key} not found`);
      }
      exports.push({ key, value: await this.decrypt(secret.value_encrypted, { scope_type: 'project', scope_id: projectId, key }) });
    }

    return exports;
  }

  /**
   * Move stored credentials to `v2` (`eve system secrets reencrypt`). New
   * writes use `v2` from here on: this process at once, other replicas
   * within half a minute. Then `v1` secrets, plain integration tokens and
   * plain OAuth client secrets are sealed in batches, each row by
   * compare-and-set on the value read, so a row written meanwhile keeps its
   * new value and is left for the next pass. A dry run only counts.
   * After this, a release that reads only `v1` cannot read these rows.
   */
  async reencrypt(options: { actor: string; dryRun?: boolean }): Promise<SecretsReencryptResponse> {
    this.ensureConfigured();
    const before = await this.storageCounts();
    const reencrypted = { secrets: 0, integration_tokens: 0, oauth_client_secrets: 0 };
    const skipped = { changed: 0, unreadable: 0 };
    if (options.dryRun) {
      return {
        dry_run: true,
        write_format: await this.cipher.writeFormat(),
        before,
        after: before,
        reencrypted,
        skipped,
        remaining: legacyCredentialRows(before),
      };
    }

    await systemSettingsQueries(this.db).set(
      SECRETS_CIPHERTEXT_FORMAT_SETTING,
      'v2',
      options.actor,
      'Format of new credential writes: v2 after eve system secrets reencrypt',
    );
    this.cipher.forgetWriteFormat();

    for (let after = ''; ;) {
      const rows = await this.secrets.listInFormat('v1', after, REENCRYPT_BATCH);
      if (rows.length === 0) break;
      for (const row of rows) {
        after = row.id;
        let sealed: string;
        try {
          sealed = this.cipher.resealSecret(row, row.value_encrypted);
        } catch {
          skipped.unreadable += 1;
          continue;
        }
        if (await this.secrets.swapCiphertext(row.id, row.value_encrypted, sealed)) reencrypted.secrets += 1;
        else skipped.changed += 1;
      }
    }

    const integrations = integrationQueries(this.db);
    for (let after = ''; ;) {
      const rows = await integrations.listPlainTokens(after, REENCRYPT_BATCH);
      if (rows.length === 0) break;
      for (const row of rows) {
        after = row.id;
        const sealed = await this.cipher.sealTokens(row.id, row.tokens_json, 'v2');
        if (await integrations.swapTokens(row.id, row.tokens_json, sealed)) reencrypted.integration_tokens += 1;
        else skipped.changed += 1;
      }
    }

    const configs = oauthAppConfigQueries(this.db);
    for (let after = ''; ;) {
      const rows = await configs.listPlainClientSecrets(after, REENCRYPT_BATCH);
      if (rows.length === 0) break;
      for (const row of rows) {
        after = row.id;
        const sealed = await this.cipher.sealColumn(
          { table: 'oauth_app_configs', id: row.id, field: 'client_secret' },
          row.client_secret,
          'v2',
        );
        if (await configs.swapClientSecret(row.id, row.client_secret, sealed)) reencrypted.oauth_client_secrets += 1;
        else skipped.changed += 1;
      }
    }

    const afterCounts = await this.storageCounts();
    return {
      dry_run: false,
      write_format: 'v2',
      before,
      after: afterCounts,
      reencrypted,
      skipped,
      remaining: legacyCredentialRows(afterCounts),
    };
  }

  private storageCounts(): Promise<SecretStorageCounts> {
    return countStoredCredentials(this.db);
  }

  private toResponse(secret: { id: string; scope_type: SecretScopeType; scope_id: string; key: string; type: SecretType; created_at: Date; updated_at: Date }): SecretResponse {
    return {
      id: secret.id,
      scope_type: secret.scope_type,
      scope_id: secret.scope_id,
      key: secret.key,
      type: secret.type,
      created_at: secret.created_at.toISOString(),
      updated_at: secret.updated_at.toISOString(),
    };
  }

  /**
   * Decrypt secrets into the resolved map, skipping any that fail decryption
   * (e.g. encrypted with a rotated master key). This prevents a single stale
   * secret from crashing the entire resolution pipeline.
   */
  private async decryptSecrets(
    secrets: Array<{ key: string; value_encrypted: string; type: SecretType }>,
    resolved: Map<string, { value: string; type: SecretType; scope_type: 'user' | 'org' | 'project' | 'system'; scope_id: string }>,
    scope: 'user' | 'org' | 'project' | 'system',
    scopeId: string,
  ): Promise<void> {
    for (const secret of secrets) {
      try {
        const value = await this.decrypt(secret.value_encrypted, { scope_type: scope, scope_id: scopeId, key: secret.key });
        resolved.set(secret.key, { value, type: secret.type, scope_type: scope, scope_id: scopeId });
      } catch (err) {
        this.logger.warn(
          `Failed to decrypt ${scope} secret "${secret.key}" — skipping (likely encrypted with a previous master key). ` +
          `Re-set this secret to re-encrypt it: eve secrets set ${secret.key} <value> --${scope === 'system' ? 'system' : scope} <id>`,
        );
      }
    }
  }

  private ensureConfigured(): void {
    if (!this.cipher.configured) {
      throw new InternalServerErrorException('Secrets master key is required to use secrets');
    }
  }

  private async ensureScopeExists(scopeType: SecretScopeType, scopeId: string): Promise<void> {
    // System scope always exists
    if (scopeType === 'system') {
      return;
    }
    if (scopeType === 'org') {
      const org = await this.orgs.findById(scopeId, { include_deleted: false });
      if (!org) {
        throw new NotFoundException(`Organization ${scopeId} not found`);
      }
    }
    if (scopeType === 'project') {
      const project = await this.projects.findById(scopeId, { include_deleted: false });
      if (!project) {
        throw new NotFoundException(`Project ${scopeId} not found`);
      }
    }
  }

  private async listAvailableSecretKeys(projectId: string, userId?: string): Promise<Set<string>> {
    const project = await this.projects.findById(projectId, { include_deleted: false });
    if (!project) {
      throw new NotFoundException(`Project ${projectId} not found`);
    }

    const keys = new Set<string>();

    const systemSecrets = await this.secrets.listByScope('system', 'system', { limit: 500, offset: 0 });
    for (const secret of systemSecrets) {
      keys.add(secret.key);
    }

    const orgSecrets = await this.secrets.listByScope('org', project.org_id, { limit: 500, offset: 0 });
    for (const secret of orgSecrets) {
      keys.add(secret.key);
    }

    if (userId) {
      const userSecrets = await this.secrets.listByScope('user', userId, { limit: 500, offset: 0 });
      for (const secret of userSecrets) {
        keys.add(secret.key);
      }
    }

    const projectSecrets = await this.secrets.listByScope('project', projectId, { limit: 500, offset: 0 });
    for (const secret of projectSecrets) {
      keys.add(secret.key);
    }

    return keys;
  }

  private encrypt(value: string, location: SecretLocation): Promise<string> {
    return this.cipher.sealSecret(location, value);
  }

  /** Open a stored value; a `v2` ciphertext opens only at its own scope and key. */
  private decrypt(payload: string, location: SecretLocation): Promise<string> {
    return this.cipher.openSecret(location, payload);
  }
}
