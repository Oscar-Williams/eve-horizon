import type { Db } from '../client.js';
import { SEALED_ENVELOPE_PATTERN } from './secrets.js';

export interface OAuthAppConfig {
  id: string;
  org_id: string;
  provider: string;
  client_id: string;
  /** Plain, or a `v2` envelope once the instance seals credentials at rest. */
  client_secret: string;
  /** `signing_secret` (Slack) is plain, or a `v2` envelope like `client_secret`. */
  config_json: Record<string, unknown>;
  label: string | null;
  status: string;
  created_by: string | null;
  created_at: Date;
  updated_at: Date;
}

export function oauthAppConfigQueries(db: Db) {
  return {
    async findByOrgAndProvider(orgId: string, provider: string): Promise<OAuthAppConfig | undefined> {
      const [row] = await db<OAuthAppConfig[]>`
        SELECT * FROM oauth_app_configs
        WHERE org_id = ${orgId} AND provider = ${provider}
        LIMIT 1
      `;
      return row;
    },

    async listByOrg(orgId: string): Promise<OAuthAppConfig[]> {
      return db<OAuthAppConfig[]>`
        SELECT * FROM oauth_app_configs
        WHERE org_id = ${orgId}
        ORDER BY provider
      `;
    },

    async upsert(
      config: Omit<OAuthAppConfig, 'created_at' | 'updated_at'>,
    ): Promise<OAuthAppConfig> {
      const [row] = await db<OAuthAppConfig[]>`
        INSERT INTO oauth_app_configs (
          id, org_id, provider, client_id, client_secret,
          config_json, label, status, created_by
        )
        VALUES (
          ${config.id},
          ${config.org_id},
          ${config.provider},
          ${config.client_id},
          ${config.client_secret},
          ${db.json(config.config_json as never)},
          ${config.label},
          ${config.status},
          ${config.created_by}
        )
        ON CONFLICT (org_id, provider) DO UPDATE SET
          client_id     = EXCLUDED.client_id,
          client_secret = EXCLUDED.client_secret,
          config_json   = EXCLUDED.config_json,
          label         = COALESCE(EXCLUDED.label, oauth_app_configs.label),
          status        = EXCLUDED.status,
          updated_at    = NOW()
        RETURNING *
      `;
      return row;
    },

    async updateClientSecret(id: string, clientSecret: string): Promise<boolean> {
      const result = await db`
        UPDATE oauth_app_configs SET client_secret = ${clientSecret} WHERE id = ${id}
      `;
      return result.count > 0;
    },

    /** Client secrets by how they are stored: plain or a whole `v2` envelope. */
    async countClientSecretFormats(): Promise<{ plain: number; sealed: number }> {
      const [row] = await db<{ plain: number; sealed: number }[]>`
        SELECT
          COUNT(*) FILTER (WHERE client_secret !~ ${SEALED_ENVELOPE_PATTERN})::int AS plain,
          COUNT(*) FILTER (WHERE client_secret ~ ${SEALED_ENVELOPE_PATTERN})::int AS sealed
        FROM oauth_app_configs
      `;
      return { plain: row?.plain ?? 0, sealed: row?.sealed ?? 0 };
    },

    /** Up to `limit` configs whose client secret is plain, after `afterId`, in id order. */
    async listPlainClientSecrets(afterId: string, limit: number): Promise<Array<{ id: string; client_secret: string }>> {
      return db<Array<{ id: string; client_secret: string }>>`
        SELECT id, client_secret FROM oauth_app_configs
        WHERE client_secret !~ ${SEALED_ENVELOPE_PATTERN} AND id > ${afterId}
        ORDER BY id
        LIMIT ${limit}
      `;
    },

    /** Replace a client secret only while it still holds `from`. */
    async swapClientSecret(id: string, from: string, to: string): Promise<boolean> {
      const result = await db`
        UPDATE oauth_app_configs SET client_secret = ${to}
        WHERE id = ${id} AND client_secret = ${from}
      `;
      return result.count > 0;
    },

    /** Set the Slack signing secret in a config, leaving the rest of `config_json`. */
    async updateSigningSecret(id: string, signingSecret: string): Promise<boolean> {
      const result = await db`
        UPDATE oauth_app_configs
        SET config_json = jsonb_set(config_json, '{signing_secret}', to_jsonb(${signingSecret}::text))
        WHERE id = ${id}
      `;
      return result.count > 0;
    },

    /** Signing secrets (`config_json.signing_secret`) by how they are stored: plain or a whole `v2` envelope. */
    async countSigningSecretFormats(): Promise<{ plain: number; sealed: number }> {
      const [row] = await db<{ plain: number; sealed: number }[]>`
        SELECT
          COUNT(*) FILTER (WHERE config_json->>'signing_secret' !~ ${SEALED_ENVELOPE_PATTERN})::int AS plain,
          COUNT(*) FILTER (WHERE config_json->>'signing_secret' ~ ${SEALED_ENVELOPE_PATTERN})::int AS sealed
        FROM oauth_app_configs
        WHERE COALESCE(config_json->>'signing_secret', '') <> ''
      `;
      return { plain: row?.plain ?? 0, sealed: row?.sealed ?? 0 };
    },

    /** Up to `limit` configs whose signing secret is plain, after `afterId`, in id order. */
    async listPlainSigningSecrets(afterId: string, limit: number): Promise<Array<{ id: string; signing_secret: string }>> {
      return db<Array<{ id: string; signing_secret: string }>>`
        SELECT id, config_json->>'signing_secret' AS signing_secret FROM oauth_app_configs
        WHERE COALESCE(config_json->>'signing_secret', '') <> ''
          AND config_json->>'signing_secret' !~ ${SEALED_ENVELOPE_PATTERN}
          AND id > ${afterId}
        ORDER BY id
        LIMIT ${limit}
      `;
    },

    /** Replace a signing secret only while it still holds `from`. */
    async swapSigningSecret(id: string, from: string, to: string): Promise<boolean> {
      const result = await db`
        UPDATE oauth_app_configs
        SET config_json = jsonb_set(config_json, '{signing_secret}', to_jsonb(${to}::text))
        WHERE id = ${id} AND config_json->>'signing_secret' = ${from}
      `;
      return result.count > 0;
    },

    async remove(orgId: string, provider: string): Promise<boolean> {
      const result = await db`
        DELETE FROM oauth_app_configs
        WHERE org_id = ${orgId} AND provider = ${provider}
      `;
      return result.count > 0;
    },
  };
}
