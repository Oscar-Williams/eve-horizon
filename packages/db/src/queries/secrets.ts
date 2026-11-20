import type { Db } from '../client.js';

export type SecretScopeType = 'user' | 'org' | 'project' | 'system';
export type SecretType = 'env_var' | 'file' | 'github_token' | 'ssh_key';

export interface Secret {
  id: string;
  scope_type: SecretScopeType;
  scope_id: string;
  key: string;
  type: SecretType;
  value_encrypted: string;
  created_at: Date;
  updated_at: Date;
}

/**
 * A whole `v2` envelope (`v2:iv:tag:data`, a 12-byte IV and 16-byte tag in
 * base64), as a pattern both Postgres and JavaScript read the same way. A
 * credential column holding anything else is plain.
 */
export const SEALED_ENVELOPE_PATTERN = '^v2:[A-Za-z0-9+/]{16}:[A-Za-z0-9+/]{22}==:[A-Za-z0-9+/]*={0,2}$';

export interface ListSecretsOptions {
  limit?: number;
  offset?: number;
}

export function secretQueries(db: Db) {
  return {
    async create(secret: Omit<Secret, 'created_at' | 'updated_at'>): Promise<Secret> {
      const [row] = await db<Secret[]>`
        INSERT INTO secrets (id, scope_type, scope_id, key, type, value_encrypted)
        VALUES (
          ${secret.id},
          ${secret.scope_type},
          ${secret.scope_id},
          ${secret.key},
          ${secret.type},
          ${secret.value_encrypted}
        )
        RETURNING *
      `;
      return row;
    },

    async listByScope(
      scopeType: SecretScopeType,
      scopeId: string,
      options: ListSecretsOptions = {},
    ): Promise<Secret[]> {
      const limit = options.limit ?? 50;
      const offset = options.offset ?? 0;
      return db<Secret[]>`
        SELECT * FROM secrets
        WHERE scope_type = ${scopeType} AND scope_id = ${scopeId}
        ORDER BY created_at DESC
        LIMIT ${limit} OFFSET ${offset}
      `;
    },

    /** The names of every secret in a scope, without their values. */
    async listKeysByScope(scopeType: SecretScopeType, scopeId: string): Promise<string[]> {
      const rows = await db<Array<{ key: string }>>`
        SELECT key FROM secrets
        WHERE scope_type = ${scopeType} AND scope_id = ${scopeId}
        ORDER BY key
      `;
      return rows.map((row) => row.key);
    },

    async findByScopeAndKey(
      scopeType: SecretScopeType,
      scopeId: string,
      key: string,
    ): Promise<Secret | null> {
      const [row] = await db<Secret[]>`
        SELECT * FROM secrets
        WHERE scope_type = ${scopeType} AND scope_id = ${scopeId} AND key = ${key}
      `;
      return row ?? null;
    },

    async updateByKey(
      scopeType: SecretScopeType,
      scopeId: string,
      key: string,
      updates: { value_encrypted?: string; type?: SecretType },
    ): Promise<Secret | null> {
      const valueEncrypted = updates.value_encrypted ?? null;
      const type = updates.type ?? null;

      const [row] = await db<Secret[]>`
        UPDATE secrets
        SET
          value_encrypted = COALESCE(${valueEncrypted}, value_encrypted),
          type = COALESCE(${type}, type),
          updated_at = NOW()
        WHERE scope_type = ${scopeType} AND scope_id = ${scopeId} AND key = ${key}
        RETURNING *
      `;
      return row ?? null;
    },

    async deleteByKey(scopeType: SecretScopeType, scopeId: string, key: string): Promise<boolean> {
      const result = await db`
        DELETE FROM secrets
        WHERE scope_type = ${scopeType} AND scope_id = ${scopeId} AND key = ${key}
      `;
      return result.count > 0;
    },

    /** Secrets by stored format (the text before the first colon: v1, v2). */
    async countByFormat(): Promise<Record<string, number>> {
      const rows = await db<{ format: string; count: number }[]>`
        SELECT split_part(value_encrypted, ':', 1) AS format, COUNT(*)::int AS count
        FROM secrets GROUP BY 1
      `;
      return Object.fromEntries(rows.map((r) => [r.format, r.count]));
    },

    /** Up to `limit` secrets stored in a format, after `afterId`, in id order. */
    async listInFormat(format: string, afterId: string, limit: number): Promise<Secret[]> {
      return db<Secret[]>`
        SELECT * FROM secrets
        WHERE value_encrypted LIKE ${`${format}:%`} AND id > ${afterId}
        ORDER BY id
        LIMIT ${limit}
      `;
    },

    /**
     * Replace a secret's ciphertext only while it still holds `from`: a row
     * written in between keeps its new value. Leaves updated_at alone, since
     * the value is the same.
     */
    async swapCiphertext(id: string, from: string, to: string): Promise<boolean> {
      const result = await db`
        UPDATE secrets SET value_encrypted = ${to}
        WHERE id = ${id} AND value_encrypted = ${from}
      `;
      return result.count > 0;
    },
  };
}
