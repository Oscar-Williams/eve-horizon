import type { Db } from '../client.js';

/**
 * Integration tokens as stored: the token object (plain), or a JSON string
 * holding a `v2` envelope once the instance seals credentials at rest. Only
 * the API opens an envelope.
 */
export type StoredIntegrationTokens = Record<string, unknown> | string | null;

export interface Integration {
  id: string;
  org_id: string;
  provider: string;
  account_id: string;
  tokens_json: StoredIntegrationTokens;
  settings_json: Record<string, unknown>;
  status: string;
  created_at: Date;
  updated_at: Date;
}

export interface ExternalIdentity {
  id: string;
  provider: string;
  account_id: string;
  external_user_id: string;
  eve_user_id: string | null;
  created_at: Date;
  updated_at: Date;
}

export interface MembershipRequest {
  id: string;
  org_id: string;
  external_identity_id: string;
  status: string;
  approved_by: string | null;
  approved_at: Date | null;
  created_at: Date;
  updated_at: Date;
}

export function integrationQueries(db: Db) {
  return {
    async listByOrg(orgId: string): Promise<Integration[]> {
      return db<Integration[]>`
        SELECT * FROM integrations
        WHERE org_id = ${orgId}
        ORDER BY created_at DESC
      `;
    },

    async findByProviderAccount(provider: string, accountId: string): Promise<Integration | undefined> {
      const [row] = await db<Integration[]>`
        SELECT * FROM integrations
        WHERE provider = ${provider} AND account_id = ${accountId}
        LIMIT 1
      `;
      return row;
    },

    async findById(id: string): Promise<Integration | undefined> {
      const [row] = await db<Integration[]>`
        SELECT * FROM integrations
        WHERE id = ${id}
        LIMIT 1
      `;
      return row;
    },

    async listActive(): Promise<Integration[]> {
      return db<Integration[]>`
        SELECT * FROM integrations WHERE status = 'active' ORDER BY created_at
      `;
    },

    /** Integrations by how their tokens are stored: a plain object or a sealed string. */
    async countTokenFormats(): Promise<{ plain: number; sealed: number }> {
      const [row] = await db<{ plain: number; sealed: number }[]>`
        SELECT
          COUNT(*) FILTER (WHERE jsonb_typeof(tokens_json) = 'object')::int AS plain,
          COUNT(*) FILTER (WHERE jsonb_typeof(tokens_json) = 'string')::int AS sealed
        FROM integrations
      `;
      return { plain: row?.plain ?? 0, sealed: row?.sealed ?? 0 };
    },

    /** Up to `limit` integrations whose tokens are stored plain, after `afterId`, in id order. */
    async listPlainTokens(afterId: string, limit: number): Promise<Array<{ id: string; tokens_json: Record<string, unknown> }>> {
      return db<Array<{ id: string; tokens_json: Record<string, unknown> }>>`
        SELECT id, tokens_json FROM integrations
        WHERE jsonb_typeof(tokens_json) = 'object' AND id > ${afterId}
        ORDER BY id
        LIMIT ${limit}
      `;
    },

    /** Replace stored tokens only while they still equal `from`. */
    async swapTokens(id: string, from: Record<string, unknown>, to: StoredIntegrationTokens): Promise<boolean> {
      const result = await db`
        UPDATE integrations SET tokens_json = ${to === null ? null : db.json(to as never)}
        WHERE id = ${id} AND tokens_json = ${db.json(from as never)}
      `;
      return result.count > 0;
    },

    async insert(integration: Omit<Integration, 'created_at' | 'updated_at'>): Promise<Integration> {
      const [row] = await db<Integration[]>`
        INSERT INTO integrations (
          id,
          org_id,
          provider,
          account_id,
          tokens_json,
          status
        )
        VALUES (
          ${integration.id},
          ${integration.org_id},
          ${integration.provider},
          ${integration.account_id},
          ${integration.tokens_json ? db.json(integration.tokens_json as never) : null},
          ${integration.status}
        )
        RETURNING *
      `;
      return row;
    },

    async updateTokens(
      id: string,
      tokensJson: StoredIntegrationTokens,
      status?: string,
    ): Promise<Integration | undefined> {
      const statusValue = status ?? null;
      const [row] = await db<Integration[]>`
        UPDATE integrations
        SET tokens_json = ${tokensJson ? db.json(tokensJson as never) : null},
            status = COALESCE(${statusValue}, status),
            updated_at = NOW()
        WHERE id = ${id}
        RETURNING *
      `;
      return row;
    },

    async updateSettings(
      id: string,
      settings: Record<string, unknown>,
    ): Promise<Integration | undefined> {
      const [row] = await db<Integration[]>`
        UPDATE integrations
        SET settings_json = settings_json || ${db.json(settings as never)},
            updated_at = NOW()
        WHERE id = ${id}
        RETURNING *
      `;
      return row;
    },
  };
}

export function externalIdentityQueries(db: Db) {
  return {
    async findByProviderAccountUser(
      provider: string,
      accountId: string,
      externalUserId: string,
    ): Promise<ExternalIdentity | undefined> {
      const [row] = await db<ExternalIdentity[]>`
        SELECT * FROM external_identities
        WHERE provider = ${provider}
          AND account_id = ${accountId}
          AND external_user_id = ${externalUserId}
        LIMIT 1
      `;
      return row;
    },

    async insert(identity: Omit<ExternalIdentity, 'created_at' | 'updated_at'>): Promise<ExternalIdentity> {
      const [row] = await db<ExternalIdentity[]>`
        INSERT INTO external_identities (
          id,
          provider,
          account_id,
          external_user_id,
          eve_user_id
        )
        VALUES (
          ${identity.id},
          ${identity.provider},
          ${identity.account_id},
          ${identity.external_user_id},
          ${identity.eve_user_id}
        )
        RETURNING *
      `;
      return row;
    },

    async updateEveUser(id: string, userId: string | null): Promise<ExternalIdentity | undefined> {
      const [row] = await db<ExternalIdentity[]>`
        UPDATE external_identities
        SET eve_user_id = ${userId},
            updated_at = NOW()
        WHERE id = ${id}
        RETURNING *
      `;
      return row;
    },
  };
}

export function membershipRequestQueries(db: Db) {
  return {
    async listByOrg(orgId: string, status?: string): Promise<MembershipRequest[]> {
      if (status) {
        return db<MembershipRequest[]>`
          SELECT * FROM membership_requests
          WHERE org_id = ${orgId} AND status = ${status}
          ORDER BY created_at DESC
        `;
      }
      return db<MembershipRequest[]>`
        SELECT * FROM membership_requests
        WHERE org_id = ${orgId}
        ORDER BY created_at DESC
      `;
    },

    async findById(id: string): Promise<MembershipRequest | undefined> {
      const [row] = await db<MembershipRequest[]>`
        SELECT * FROM membership_requests
        WHERE id = ${id}
        LIMIT 1
      `;
      return row;
    },

    async insert(request: Omit<MembershipRequest, 'created_at' | 'updated_at'>): Promise<MembershipRequest> {
      const [row] = await db<MembershipRequest[]>`
        INSERT INTO membership_requests (
          id,
          org_id,
          external_identity_id,
          status,
          approved_by,
          approved_at
        )
        VALUES (
          ${request.id},
          ${request.org_id},
          ${request.external_identity_id},
          ${request.status},
          ${request.approved_by},
          ${request.approved_at}
        )
        RETURNING *
      `;
      return row;
    },

    async updateStatus(
      id: string,
      status: string,
      approvedBy: string | null,
      approvedAt: Date | null,
    ): Promise<MembershipRequest | undefined> {
      const [row] = await db<MembershipRequest[]>`
        UPDATE membership_requests
        SET status = ${status},
            approved_by = ${approvedBy},
            approved_at = ${approvedAt},
            updated_at = NOW()
        WHERE id = ${id}
        RETURNING *
      `;
      return row;
    },

    async findPendingByIdentity(identityId: string): Promise<MembershipRequest | undefined> {
      const [row] = await db<MembershipRequest[]>`
        SELECT * FROM membership_requests
        WHERE external_identity_id = ${identityId}
          AND status = 'pending'
        ORDER BY created_at DESC
        LIMIT 1
      `;
      return row;
    },
  };
}
