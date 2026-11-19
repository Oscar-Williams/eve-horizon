import {
  Inject,
  Injectable,
  NotFoundException,
  ConflictException,
  BadRequestException,
  ForbiddenException,
  HttpException,
  InternalServerErrorException,
  Optional,
} from '@nestjs/common';
import * as crypto from 'crypto';
import type { Db, Integration } from '@eve/db';
import {
  integrationQueries,
  externalIdentityQueries,
  membershipRequestQueries,
  userQueries,
  membershipQueries,
  oauthAppConfigQueries,
  oauthStateQueries,
} from '@eve/db';
import type { OAuthAppConfig } from '@eve/db';
import { SecurityService } from '../security/security.service.js';
import { SecretCipher } from '../secrets/secret-cipher.js';
import { platformSigningKeys } from '../common/platform-signing-key.js';
import {
  generateIntegrationId,
  generateExternalIdentityId,
  generateMembershipRequestId,
  generateUserId,
  generateOAuthAppConfigId,
  loadConfig,
  createJsonLogger,
  type IntegrationResponse,
  type SlackConnectRequest,
  type MembershipRequestResponse,
  type OAuthAppConfigResponse,
  type CreateOAuthAppConfigRequest,
  type ProviderSetupInfoResponse,
} from '@eve/shared';

const logger = createJsonLogger('api');

/** Providers with an OAuth install flow. */
export type OAuthProvider = 'slack' | 'google_drive';

/** Binds a signed-link Slack install (no Eve user) to the browser that started it. */
export const SLACK_INSTALL_COOKIE = '__Host-eve_slack_install';

/** With authentication disabled (local development) there is no caller: one stand-in user starts and completes. */
export const OAUTH_NO_AUTH_USER = 'anonymous';

/** The state and the install cookie live ten minutes. */
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

/** A provider name from a route: 'slack', 'google-drive' or 'google_drive'. */
export function oauthProvider(value: string): OAuthProvider {
  const normalized = value.replace(/-/g, '_');
  if (normalized === 'slack' || normalized === 'google_drive') return normalized;
  throw new NotFoundException(`Unknown OAuth provider: ${value}`);
}

/** Where the provider sends the browser back to. */
export function oauthRedirectUri(provider: OAuthProvider): string | undefined {
  const config = loadConfig();
  const apiUrl = config.EVE_API_URL ?? process.env.EVE_API_URL;
  if (!apiUrl) return undefined;
  return `${apiUrl}/integrations/${provider === 'slack' ? 'slack' : 'google-drive'}/oauth/callback`;
}

/** What the public callback answers: waiting for the user to complete, or done (signed-link install). */
export type OAuthCallbackResult =
  | { ok: true; pending: true; message: string }
  | { ok: true; pending?: undefined; integration_id: string; account_id: string; team_id?: string };

function sha256(value: string): string {
  return crypto.createHash('sha256').update(value).digest('hex');
}

@Injectable()
export class IntegrationsService {
  private integrations: ReturnType<typeof integrationQueries>;
  private externalIdentities: ReturnType<typeof externalIdentityQueries>;
  private membershipRequests: ReturnType<typeof membershipRequestQueries>;
  private users: ReturnType<typeof userQueries>;
  private memberships: ReturnType<typeof membershipQueries>;
  private oauthAppConfigs: ReturnType<typeof oauthAppConfigQueries>;
  private oauthStates: ReturnType<typeof oauthStateQueries>;
  /** Integration tokens and OAuth client secrets are sealed at rest once the instance writes v2. */
  private readonly cipher: SecretCipher;

  /** Track redeemed link token JTIs (in-memory, sufficient for pre-MVP). */
  private redeemedJtis = new Set<string>();

  constructor(
    @Inject('DB') private readonly db: Db,
    @Optional() security?: SecurityService,
  ) {
    this.integrations = integrationQueries(db);
    this.externalIdentities = externalIdentityQueries(db);
    this.membershipRequests = membershipRequestQueries(db);
    this.users = userQueries(db);
    this.memberships = membershipQueries(db);
    this.oauthAppConfigs = oauthAppConfigQueries(db);
    this.oauthStates = oauthStateQueries(db);
    this.cipher = new SecretCipher(db, security);
  }

  // ---------------------------------------------------------------------------
  // Integration CRUD
  // ---------------------------------------------------------------------------

  async listByOrg(orgId: string): Promise<IntegrationResponse[]> {
    const rows = await this.integrations.listByOrg(orgId);
    return rows.map((row: {
      id: string;
      org_id: string;
      provider: string;
      account_id: string;
      status: string;
      created_at: Date;
      updated_at: Date;
    }) => this.toResponse(row));
  }

  async connectSlack(orgId: string, payload: SlackConnectRequest): Promise<IntegrationResponse> {
    const existing = await this.integrations.findByProviderAccount('slack', payload.team_id);
    if (existing) {
      if (existing.org_id !== orgId) {
        throw new NotFoundException('Slack integration belongs to a different org');
      }
      const nextTokens = payload.tokens_json === undefined
        ? await this.cipher.openTokens(existing.id, existing.tokens_json)
        : payload.tokens_json ?? null;
      const updated = await this.integrations.updateTokens(
        existing.id,
        await this.cipher.sealTokens(existing.id, nextTokens ?? null),
        payload.status ?? existing.status,
      );
      return this.toResponse(updated ?? existing);
    }

    const id = generateIntegrationId();
    const created = await this.integrations.insert({
      id,
      org_id: orgId,
      provider: 'slack',
      account_id: payload.team_id,
      tokens_json: await this.cipher.sealTokens(id, payload.tokens_json ?? null),
      settings_json: {},
      status: payload.status ?? 'active',
    });

    return this.toResponse(created);
  }

  async connectProvider(
    orgId: string,
    provider: string,
    accountId: string,
    tokensJson: Record<string, unknown> | null,
    status: string = 'active',
  ): Promise<IntegrationResponse> {
    const existing = await this.integrations.findByProviderAccount(provider, accountId);
    if (existing) {
      if (existing.org_id !== orgId) {
        throw new NotFoundException(`${provider} integration belongs to a different org`);
      }
      const nextTokens = tokensJson ?? (await this.cipher.openTokens(existing.id, existing.tokens_json));
      const updated = await this.integrations.updateTokens(
        existing.id,
        await this.cipher.sealTokens(existing.id, nextTokens ?? null),
        status,
      );
      return this.toResponse(updated ?? existing);
    }

    const id = generateIntegrationId();
    const created = await this.integrations.insert({
      id,
      org_id: orgId,
      provider,
      account_id: accountId,
      tokens_json: await this.cipher.sealTokens(id, tokensJson),
      settings_json: {},
      status,
    });

    return this.toResponse(created);
  }

  async testIntegration(id: string, orgId: string): Promise<{ ok: boolean; detail?: string }> {
    const existing = await this.integrations.findById(id);
    if (!existing) {
      throw new NotFoundException(`Integration ${id} not found`);
    }
    if (existing.org_id !== orgId) {
      throw new NotFoundException(`Integration ${id} not found in org ${orgId}`);
    }

    // For Slack: verify the bot token is active via auth.test
    const tokens = existing.provider === 'slack'
      ? await this.cipher.openTokens(existing.id, existing.tokens_json)
      : null;
    if (existing.provider === 'slack' && tokens) {
      const token = (typeof tokens.access_token === 'string' && tokens.access_token)
        || (typeof tokens.bot_token === 'string' && tokens.bot_token);
      if (token) {
        try {
          const resp = await fetch('https://slack.com/api/auth.test', {
            method: 'POST',
            headers: { authorization: `Bearer ${token}` },
          });
          const data = await resp.json() as { ok?: boolean; error?: string; team?: string; user?: string };
          if (!data.ok) {
            return { ok: false, detail: `Slack auth.test failed: ${data.error ?? 'unknown'}` };
          }
          return { ok: true, detail: `Slack token active (team: ${data.team ?? 'unknown'})` };
        } catch (err) {
          return { ok: false, detail: `Slack auth.test error: ${err instanceof Error ? err.message : String(err)}` };
        }
      }
      return { ok: false, detail: 'No bot token found in integration tokens' };
    }

    return { ok: true };
  }

  async listActiveIntegrations(): Promise<Array<{
    id: string; org_id: string; provider: string;
    account_id: string; tokens_json: Record<string, unknown> | null;
    settings_json: Record<string, unknown>; status: string;
  }>> {
    const stored = await this.integrations.listActive();
    const rows: Array<{
      id: string; org_id: string; provider: string;
      account_id: string; tokens_json: Record<string, unknown> | null;
      settings_json: Record<string, unknown>; status: string;
    }> = [];
    for (const row of stored) {
      rows.push({
        id: row.id,
        org_id: row.org_id,
        provider: row.provider,
        account_id: row.account_id,
        tokens_json: await this.openTokensOrNull(row),
        settings_json: row.settings_json ?? {},
        status: row.status,
      });
    }

    // Enrich Slack integrations with the per-org signing secret from oauth_app_configs
    for (const row of rows) {
      if (row.provider === 'slack') {
        const appConfig = await this.oauthAppConfigs.findByOrgAndProvider(row.org_id, 'slack');
        if (appConfig?.config_json && (appConfig.config_json as Record<string, unknown>).signing_secret) {
          row.settings_json = {
            ...row.settings_json,
            signing_secret: (appConfig.config_json as Record<string, unknown>).signing_secret,
          };
        }
      }
    }

    return rows;
  }

  async resolveIntegration(provider: string, accountId: string): Promise<{ integration_id: string; org_id: string }> {
    const integration = await this.integrations.findByProviderAccount(provider, accountId);
    if (!integration) {
      throw new NotFoundException(`Integration not found for ${provider}:${accountId}`);
    }
    return { integration_id: integration.id, org_id: integration.org_id };
  }

  /** An integration's tokens, opened: the internal routes decrypt before replying. */
  async getIntegrationTokens(integrationId: string): Promise<Record<string, unknown> | null> {
    const integration = await this.integrations.findById(integrationId);
    if (!integration) {
      throw new NotFoundException(`Integration ${integrationId} not found`);
    }
    return this.cipher.openTokens(integration.id, integration.tokens_json);
  }

  /** For listings: one row whose tokens cannot be opened must not hide the rest. */
  private async openTokensOrNull(row: Integration): Promise<Record<string, unknown> | null> {
    try {
      return await this.cipher.openTokens(row.id, row.tokens_json);
    } catch (error) {
      logger.warn({
        event: 'integrations.tokens_unreadable',
        integrationId: row.id,
        error: error instanceof Error ? error.message : String(error),
      });
      return null;
    }
  }

  // ---------------------------------------------------------------------------
  // Integration settings
  // ---------------------------------------------------------------------------

  async updateSettings(integrationId: string, orgId: string, settings: Record<string, unknown>): Promise<IntegrationResponse> {
    const existing = await this.integrations.findById(integrationId);
    if (!existing || existing.org_id !== orgId) {
      throw new NotFoundException(`Integration ${integrationId} not found in org ${orgId}`);
    }
    const updated = await this.integrations.updateSettings(integrationId, settings);
    return this.toResponse(updated ?? existing);
  }

  async getSettings(integrationId: string): Promise<Record<string, unknown>> {
    const existing = await this.integrations.findById(integrationId);
    if (!existing) {
      throw new NotFoundException(`Integration ${integrationId} not found`);
    }
    return existing.settings_json ?? {};
  }

  // ---------------------------------------------------------------------------
  // External identity resolution (Tier 1: email auto-match)
  // ---------------------------------------------------------------------------

  async resolveExternalIdentity(
    orgId: string,
    provider: string,
    accountId: string,
    externalUserId: string,
    externalEmail?: string,
  ): Promise<{ external_identity_id: string; eve_user_id: string | null; membership_request_id: string | null }> {
    let identity = await this.externalIdentities.findByProviderAccountUser(provider, accountId, externalUserId);
    if (!identity) {
      identity = await this.externalIdentities.insert({
        id: generateExternalIdentityId(),
        provider,
        account_id: accountId,
        external_user_id: externalUserId,
        eve_user_id: null,
      });
    }

    if (identity.eve_user_id) {
      return {
        external_identity_id: identity.id,
        eve_user_id: identity.eve_user_id,
        membership_request_id: null,
      };
    }

    // Tier 1: Email auto-match — if caller provided an email, try to match
    if (externalEmail) {
      const eveUser = await this.users.findByEmail(externalEmail);
      if (eveUser) {
        const membership = await this.memberships.findOrgMembership(eveUser.id, orgId);
        if (membership) {
          await this.externalIdentities.updateEveUser(identity.id, eveUser.id);
          logger.log({
            event: 'identity.auto_matched',
            externalIdentityId: identity.id,
            eveUserId: eveUser.id,
            matchedBy: 'email',
          });
          return {
            external_identity_id: identity.id,
            eve_user_id: eveUser.id,
            membership_request_id: null,
          };
        }
        logger.log({
          event: 'identity.auto_match_skipped',
          externalIdentityId: identity.id,
          reason: 'email_matches_non_member',
          email: externalEmail,
        });
      }
    }

    const existingRequest = await this.membershipRequests.findPendingByIdentity(identity.id);
    if (existingRequest) {
      return {
        external_identity_id: identity.id,
        eve_user_id: null,
        membership_request_id: existingRequest.id,
      };
    }

    const request = await this.membershipRequests.insert({
      id: generateMembershipRequestId(),
      org_id: orgId,
      external_identity_id: identity.id,
      status: 'pending',
      approved_by: null,
      approved_at: null,
    });

    logger.log({
      event: 'identity.membership_requested',
      externalIdentityId: identity.id,
      membershipRequestId: request.id,
      orgId,
    });

    return {
      external_identity_id: identity.id,
      eve_user_id: null,
      membership_request_id: request.id,
    };
  }

  // ---------------------------------------------------------------------------
  // Membership requests (Tier 3: admin approval)
  // ---------------------------------------------------------------------------

  async listMembershipRequests(orgId: string, status?: string): Promise<MembershipRequestResponse[]> {
    const rows = await this.membershipRequests.listByOrg(orgId, status);
    return rows.map((r) => this.toMembershipRequestResponse(r));
  }

  async approveMembershipRequest(
    requestId: string,
    orgId: string,
    approvedBy: string,
    role: string = 'member',
    email?: string,
  ): Promise<MembershipRequestResponse> {
    const request = await this.membershipRequests.findById(requestId);
    if (!request || request.org_id !== orgId) {
      throw new NotFoundException(`Membership request ${requestId} not found`);
    }
    if (request.status !== 'pending') {
      throw new ConflictException(`Membership request ${requestId} is already ${request.status}`);
    }

    // Look up the external identity to get the external user info
    const identity = await this.externalIdentities.findByProviderAccountUser(
      // We need the identity by ID, but we only have findByProviderAccountUser.
      // Use a direct lookup.
      '', '', '',
    ).catch(() => null);

    // Direct identity lookup by scanning (the identity id is on the request)
    // Since we don't have findById on external identities, find it via the request
    // Actually, let's look up the identity differently. We have the external_identity_id.
    // We need to add a findById to external identities. For now, do a direct DB query.
    const [identityRow] = await this.db<{ id: string; provider: string; account_id: string; external_user_id: string; eve_user_id: string | null }[]>`
      SELECT * FROM external_identities WHERE id = ${request.external_identity_id} LIMIT 1
    `;

    if (!identityRow) {
      throw new NotFoundException(`External identity not found for request ${requestId}`);
    }

    // Determine the email for user creation
    const userEmail = email ?? `${identityRow.external_user_id}@${identityRow.provider}.external`;

    // Find or create the Eve user
    let user = await this.users.findByEmail(userEmail);
    if (!user) {
      user = await this.users.create({
        id: generateUserId(),
        email: userEmail,
        display_name: null,
        is_admin: false,
      });
    }

    // Create org membership
    await this.memberships.upsertOrgMembership(orgId, user.id, role as 'admin' | 'member');

    // Bind the external identity
    await this.externalIdentities.updateEveUser(identityRow.id, user.id);

    // Mark request approved
    const updated = await this.membershipRequests.updateStatus(
      requestId, 'approved', approvedBy, new Date(),
    );

    logger.log({
      event: 'identity.membership_approved',
      requestId,
      eveUserId: user.id,
      orgId,
      approvedBy,
    });

    return this.toMembershipRequestResponse(updated ?? request);
  }

  async denyMembershipRequest(
    requestId: string,
    orgId: string,
    deniedBy: string,
  ): Promise<MembershipRequestResponse> {
    const request = await this.membershipRequests.findById(requestId);
    if (!request || request.org_id !== orgId) {
      throw new NotFoundException(`Membership request ${requestId} not found`);
    }
    if (request.status !== 'pending') {
      throw new ConflictException(`Membership request ${requestId} is already ${request.status}`);
    }

    const updated = await this.membershipRequests.updateStatus(
      requestId, 'denied', deniedBy, new Date(),
    );

    logger.log({
      event: 'identity.membership_denied',
      requestId,
      orgId,
      deniedBy,
    });

    return this.toMembershipRequestResponse(updated ?? request);
  }

  // ---------------------------------------------------------------------------
  // Identity link tokens (Tier 2: self-service CLI claim)
  // ---------------------------------------------------------------------------

  generateLinkToken(eveUserId: string, provider: string, orgId: string): { token: string; expiresIn: number } {
    const secret = platformSigningKeys('identity-link').sign;
    if (!secret) {
      throw new BadRequestException('Internal API key not configured');
    }

    const jti = crypto.randomUUID();
    const expiresIn = 900; // 15 minutes
    const payload = {
      eve_user_id: eveUserId,
      provider,
      org_id: orgId,
      jti,
      exp: Math.floor(Date.now() / 1000) + expiresIn,
      iat: Math.floor(Date.now() / 1000),
    };

    // Simple HMAC-signed token (no JWT library dependency needed)
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
    const token = `eve-link-${payloadB64}.${sig}`;

    return { token, expiresIn };
  }

  async redeemLinkToken(
    token: string,
    provider: string,
    accountId: string,
    externalUserId: string,
  ): Promise<{ ok: boolean; external_identity_id?: string; error?: string }> {
    const secrets = platformSigningKeys('identity-link').verify;
    if (secrets.length === 0) {
      return { ok: false, error: 'Internal API key not configured' };
    }

    // Strip prefix and split
    const raw = token.startsWith('eve-link-') ? token.slice('eve-link-'.length) : token;
    const dotIdx = raw.lastIndexOf('.');
    if (dotIdx < 0) {
      return { ok: false, error: 'Invalid token format' };
    }

    const payloadB64 = raw.slice(0, dotIdx);
    const sig = raw.slice(dotIdx + 1);

    // Verify signature
    if (!signatureMatches(secrets, payloadB64, sig)) {
      return { ok: false, error: 'Invalid token signature' };
    }

    // Parse payload
    let payload: { eve_user_id: string; provider: string; org_id: string; jti: string; exp: number };
    try {
      payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch {
      return { ok: false, error: 'Invalid token payload' };
    }

    // Check expiry
    if (payload.exp < Math.floor(Date.now() / 1000)) {
      return { ok: false, error: 'Token expired' };
    }

    // Check single-use
    if (this.redeemedJtis.has(payload.jti)) {
      return { ok: false, error: 'Token already redeemed' };
    }

    // Check provider match
    if (payload.provider !== provider) {
      return { ok: false, error: `Token is for provider "${payload.provider}", not "${provider}"` };
    }

    // Find or create external identity
    let identity = await this.externalIdentities.findByProviderAccountUser(provider, accountId, externalUserId);
    if (!identity) {
      identity = await this.externalIdentities.insert({
        id: generateExternalIdentityId(),
        provider,
        account_id: accountId,
        external_user_id: externalUserId,
        eve_user_id: null,
      });
    }

    // Reject if already bound
    if (identity.eve_user_id) {
      return { ok: false, error: 'This external identity is already linked to an Eve account' };
    }

    // Bind
    await this.externalIdentities.updateEveUser(identity.id, payload.eve_user_id);
    this.redeemedJtis.add(payload.jti);

    // Clean up old JTIs after 1 hour
    setTimeout(() => this.redeemedJtis.delete(payload.jti), 3600_000);

    logger.log({
      event: 'identity.link_redeemed',
      externalIdentityId: identity.id,
      eveUserId: payload.eve_user_id,
      provider,
    });

    return { ok: true, external_identity_id: identity.id };
  }

  // ---------------------------------------------------------------------------
  // Response serialization
  // ---------------------------------------------------------------------------

  private toResponse(row: {
    id: string;
    org_id: string;
    provider: string;
    account_id: string;
    status: string;
    created_at: Date;
    updated_at: Date;
  }): IntegrationResponse {
    return {
      id: row.id,
      org_id: row.org_id,
      provider: row.provider,
      account_id: row.account_id,
      status: row.status,
      created_at: row.created_at.toISOString(),
      updated_at: row.updated_at.toISOString(),
    };
  }

  private toMembershipRequestResponse(row: {
    id: string;
    org_id: string;
    external_identity_id: string;
    status: string;
    approved_by: string | null;
    approved_at: Date | null;
    created_at: Date;
    updated_at: Date;
  }): MembershipRequestResponse {
    return {
      id: row.id,
      org_id: row.org_id,
      external_identity_id: row.external_identity_id,
      status: row.status,
      approved_by: row.approved_by,
      approved_at: row.approved_at?.toISOString() ?? null,
      created_at: row.created_at.toISOString(),
      updated_at: row.updated_at.toISOString(),
    };
  }

  // ---------------------------------------------------------------------------
  // OAuth app configs (per-org BYOA credentials)
  // ---------------------------------------------------------------------------

  /** An org's OAuth app config, with its client secret opened. */
  async getOAuthAppConfig(orgId: string, provider: string): Promise<OAuthAppConfig | undefined> {
    const config = await this.oauthAppConfigs.findByOrgAndProvider(orgId, provider);
    return config ? this.openClientSecret(config) : undefined;
  }

  async listOAuthAppConfigs(orgId: string): Promise<OAuthAppConfig[]> {
    const configs = await this.oauthAppConfigs.listByOrg(orgId);
    return Promise.all(configs.map((config) => this.openClientSecret(config)));
  }

  private async openClientSecret(config: OAuthAppConfig): Promise<OAuthAppConfig> {
    const location = { table: 'oauth_app_configs' as const, id: config.id, field: 'client_secret' as const };
    return { ...config, client_secret: await this.cipher.openColumn(location, config.client_secret) };
  }

  async upsertOAuthAppConfig(
    orgId: string,
    provider: string,
    payload: CreateOAuthAppConfigRequest,
    createdBy?: string,
  ): Promise<OAuthAppConfigResponse> {
    // The envelope is bound to the row id: an existing config keeps its own.
    const existing = await this.oauthAppConfigs.findByOrgAndProvider(orgId, provider);
    const id = existing?.id ?? generateOAuthAppConfigId();
    const seal = (rowId: string) => this.cipher.sealColumn(
      { table: 'oauth_app_configs', id: rowId, field: 'client_secret' },
      payload.client_secret,
    );
    const sealed = await seal(id);
    const config = await this.oauthAppConfigs.upsert({
      id,
      org_id: orgId,
      provider,
      client_id: payload.client_id,
      client_secret: sealed,
      config_json: payload.config ?? {},
      label: payload.label ?? null,
      status: 'active',
      created_by: createdBy ?? null,
    });
    if (config.id !== id && sealed !== payload.client_secret) {
      // Another write created the row first: seal again for the row that stands.
      await this.oauthAppConfigs.updateClientSecret(config.id, await seal(config.id));
    }
    return this.toOAuthAppConfigResponse(config);
  }

  async removeOAuthAppConfig(orgId: string, provider: string): Promise<boolean> {
    return this.oauthAppConfigs.remove(orgId, provider);
  }

  getProviderSetupInfo(provider: string): ProviderSetupInfoResponse {
    const config = loadConfig();
    const apiUrl = config.EVE_API_URL ?? process.env.EVE_API_URL ?? '';

    switch (provider) {
      case 'google_drive':
        return {
          provider: 'google_drive',
          callback_url: `${apiUrl}/integrations/google-drive/oauth/callback`,
          webhook_url: null,
          required_scopes: ['https://www.googleapis.com/auth/drive'],
          setup_instructions: [
            '1. Go to https://console.cloud.google.com',
            '2. Create a new project (or select existing)',
            '3. Enable the Google Drive API (APIs & Services > Library)',
            '4. Configure OAuth consent screen (APIs & Services > OAuth consent screen)',
            '5. Create OAuth credentials (APIs & Services > Credentials > Create > OAuth client ID)',
            '6. Application type: Web application',
            `7. Authorized redirect URI: ${apiUrl}/integrations/google-drive/oauth/callback`,
            '8. Copy Client ID and Client Secret',
            '9. Run: eve integrations configure google-drive --client-id "..." --client-secret "..."',
          ].join('\n'),
        };
      case 'slack':
        return {
          provider: 'slack',
          callback_url: `${apiUrl}/integrations/slack/oauth/callback`,
          webhook_url: `${apiUrl}/gateway/providers/slack/webhook`,
          required_scopes: [
            'app_mentions:read', 'chat:write', 'chat:write.public',
            'channels:history', 'channels:read',
            'groups:history', 'groups:read',
            'im:history', 'im:read', 'im:write',
            'users:read', 'users:read.email',
            'reactions:read', 'files:read',
          ],
          setup_instructions: [
            '1. Go to https://api.slack.com/apps',
            '2. Click "Create New App" > "From scratch"',
            '3. Configure OAuth & Permissions: add bot scopes and redirect URL',
            `4. Redirect URL: ${apiUrl}/integrations/slack/oauth/callback`,
            '5. Configure Event Subscriptions if needed',
            '6. Copy App ID, Client ID, Client Secret, Signing Secret',
            '7. Run: eve integrations configure slack --client-id "..." --client-secret "..." --signing-secret "..."',
          ].join('\n'),
        };
      default:
        throw new NotFoundException(`Unknown provider: ${provider}`);
    }
  }

  private toOAuthAppConfigResponse(row: OAuthAppConfig): OAuthAppConfigResponse {
    return {
      id: row.id,
      org_id: row.org_id,
      provider: row.provider,
      client_id: row.client_id,
      label: row.label,
      status: row.status,
      has_signing_secret: !!(row.config_json as Record<string, unknown>)?.signing_secret,
      created_at: row.created_at instanceof Date ? row.created_at.toISOString() : String(row.created_at),
      updated_at: row.updated_at instanceof Date ? row.updated_at.toISOString() : String(row.updated_at),
    };
  }

  // ---------------------------------------------------------------------------
  // OAuth state: stored with its expiry, bound to who started the install
  // ---------------------------------------------------------------------------

  /** Start an install for an Eve user: only that user can complete it. */
  async createOAuthState(provider: OAuthProvider, orgId: string, userId: string): Promise<string> {
    const state = crypto.randomBytes(32).toString('hex');
    await this.oauthStates.deleteExpired();
    await this.oauthStates.create({
      id: sha256(state),
      provider,
      org_id: orgId,
      user_id: userId,
      install_binding: null,
      expires_at: new Date(Date.now() + OAUTH_STATE_TTL_MS),
    });
    return state;
  }

  /**
   * Start a signed-link Slack install, which has no Eve user: the state is
   * bound to a cookie for the browser that started it.
   */
  async createInstallOAuthState(orgId: string): Promise<{ state: string; cookie: string; maxAgeSeconds: number }> {
    const state = crypto.randomBytes(32).toString('hex');
    const cookie = crypto.randomBytes(32).toString('base64url');
    await this.oauthStates.deleteExpired();
    await this.oauthStates.create({
      id: sha256(state),
      provider: 'slack',
      org_id: orgId,
      user_id: null,
      install_binding: sha256(cookie),
      expires_at: new Date(Date.now() + OAUTH_STATE_TTL_MS),
    });
    return { state, cookie, maxAgeSeconds: OAUTH_STATE_TTL_MS / 1000 };
  }

  /**
   * The provider's redirect back, which is public. For an install a user
   * started, it records the code and exchanges nothing: that user completes
   * it (completeOAuth). A signed-link install completes here, and only for
   * the browser holding its cookie.
   */
  async acceptOAuthCallback(
    provider: OAuthProvider,
    state: string,
    code: string,
    installCookie?: string,
  ): Promise<OAuthCallbackResult> {
    const id = sha256(state);
    const row = await this.oauthStates.find(id);
    if (!row || row.provider !== provider || row.expires_at.getTime() <= Date.now()) {
      throw new BadRequestException('Invalid or expired state token');
    }

    if (row.install_binding !== null) {
      if (!installCookie || !crypto.timingSafeEqual(Buffer.from(sha256(installCookie)), Buffer.from(row.install_binding))) {
        throw new ForbiddenException('Finish this install in the browser that started it');
      }
      const taken = await this.oauthStates.consumeForInstall(id, row.install_binding);
      if (!taken) throw new BadRequestException('Invalid or expired state token');
      return { ok: true, ...(await this.exchangeOAuthCode(provider, taken.org_id, code)) };
    }

    if (!(await this.oauthStates.recordCode(id, code))) {
      throw new BadRequestException('Invalid or expired state token');
    }
    return {
      ok: true,
      pending: true,
      message: 'Authorised. Return to the client that started this install to finish it.',
    };
  }

  /**
   * Finish an install: only the user who started it, once the provider has
   * sent the browser back with a code (409 before then).
   */
  async completeOAuth(
    providerName: string,
    state: string,
    userId: string,
  ): Promise<{ ok: true; provider: OAuthProvider; integration_id: string; account_id: string }> {
    const provider = oauthProvider(providerName);
    const id = sha256(state);
    const row = await this.oauthStates.find(id);
    if (!row || row.provider !== provider || row.expires_at.getTime() <= Date.now()) {
      throw new BadRequestException('Invalid or expired state token');
    }
    if (row.user_id !== userId) {
      throw new ForbiddenException('Only the user who started this install can complete it');
    }
    if (row.code === null) {
      throw new ConflictException('Not authorised yet: approve the install in the browser, then complete it');
    }
    const taken = await this.oauthStates.consumeForUser(id, userId);
    if (!taken?.code) throw new BadRequestException('Invalid or expired state token');
    const connected = await this.exchangeOAuthCode(provider, taken.org_id, taken.code);
    return { ok: true, provider, integration_id: connected.integration_id, account_id: connected.account_id };
  }

  /** Exchange a provider code with the org's own OAuth app, and store the integration. */
  private async exchangeOAuthCode(
    provider: OAuthProvider,
    orgId: string,
    code: string,
  ): Promise<{ integration_id: string; account_id: string; team_id?: string }> {
    const appConfig = await this.getOAuthAppConfig(orgId, provider);
    if (!appConfig) {
      throw new InternalServerErrorException(`${provider === 'slack' ? 'Slack' : 'Google Drive'} OAuth app not configured for this org`);
    }
    try {
      return provider === 'slack'
        ? await this.exchangeSlackCode(orgId, appConfig, code)
        : await this.exchangeGoogleDriveCode(orgId, appConfig, code);
    } catch (err) {
      if (err instanceof HttpException) throw err;
      logger.warn({
        event: `${provider}.oauth.callback_error`,
        error: err instanceof Error ? err.message : String(err),
      });
      throw new InternalServerErrorException('Internal error during OAuth callback');
    }
  }

  private async exchangeSlackCode(
    orgId: string,
    appConfig: OAuthAppConfig,
    code: string,
  ): Promise<{ integration_id: string; account_id: string; team_id: string }> {
    const redirectUri = oauthRedirectUri('slack');
    const params: Record<string, string> = {
      client_id: appConfig.client_id,
      client_secret: appConfig.client_secret,
      code,
    };
    if (redirectUri) params.redirect_uri = redirectUri;

    const tokenResp = await fetch('https://slack.com/api/oauth.v2.access', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(params),
    });

    const tokenData = await tokenResp.json() as {
      ok?: boolean;
      error?: string;
      team?: { id: string; name?: string };
      access_token?: string;
      bot_user_id?: string;
      authed_user?: { id: string; access_token?: string };
    };

    if (!tokenData.ok || !tokenData.team?.id) {
      logger.warn({ event: 'slack.oauth.token_exchange_failed', error: tokenData.error });
      throw new BadRequestException(`Slack token exchange failed: ${tokenData.error ?? 'unknown'}`);
    }

    const integration = await this.connectSlack(orgId, {
      team_id: tokenData.team.id,
      tokens_json: {
        access_token: tokenData.access_token,
        bot_user_id: tokenData.bot_user_id,
        team_id: tokenData.team.id,
        team_name: tokenData.team.name,
        authed_user: tokenData.authed_user,
      },
      status: 'active',
    });

    logger.log({ event: 'slack.oauth.connected', orgId, teamId: tokenData.team.id, integrationId: integration.id });
    return { integration_id: integration.id, account_id: tokenData.team.id, team_id: tokenData.team.id };
  }

  private async exchangeGoogleDriveCode(
    orgId: string,
    appConfig: OAuthAppConfig,
    code: string,
  ): Promise<{ integration_id: string; account_id: string }> {
    const redirectUri = oauthRedirectUri('google_drive');
    const tokenParams: Record<string, string> = {
      client_id: appConfig.client_id,
      client_secret: appConfig.client_secret,
      code,
      grant_type: 'authorization_code',
    };
    if (redirectUri) tokenParams.redirect_uri = redirectUri;

    const tokenResp = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams(tokenParams),
    });

    const tokenData = (await tokenResp.json()) as {
      access_token?: string;
      refresh_token?: string;
      token_type?: string;
      expires_in?: number;
      scope?: string;
      error?: string;
      error_description?: string;
    };

    if (tokenData.error || !tokenData.access_token) {
      logger.warn({
        event: 'google_drive.oauth.token_exchange_failed',
        error: tokenData.error,
        description: tokenData.error_description,
      });
      throw new BadRequestException(
        `Google token exchange failed: ${tokenData.error_description ?? tokenData.error ?? 'unknown'}`,
      );
    }

    // Fetch user info from Google Drive to get account identifier
    const aboutResp = await fetch(
      'https://www.googleapis.com/drive/v3/about?fields=user',
      { headers: { Authorization: `Bearer ${tokenData.access_token}` } },
    );

    if (!aboutResp.ok) {
      const body = await aboutResp.text().catch(() => '<unreadable>');
      logger.warn({ event: 'google_drive.oauth.about_failed', status: aboutResp.status, body });
      throw new InternalServerErrorException('Failed to fetch Google Drive user info');
    }

    const aboutData = (await aboutResp.json()) as {
      user?: { emailAddress?: string; displayName?: string; permissionId?: string };
    };

    const accountId = aboutData.user?.emailAddress ?? aboutData.user?.permissionId ?? 'unknown';

    const integration = await this.connectProvider(orgId, 'google_drive', accountId, {
      access_token: tokenData.access_token,
      refresh_token: tokenData.refresh_token,
      token_type: tokenData.token_type,
      expiry_date: Date.now() + (tokenData.expires_in ?? 3600) * 1000,
      scope: tokenData.scope,
      email: aboutData.user?.emailAddress,
      display_name: aboutData.user?.displayName,
    });

    logger.log({ event: 'google_drive.oauth.connected', orgId, accountId, integrationId: integration.id });
    return { integration_id: integration.id, account_id: accountId };
  }

  // ---------------------------------------------------------------------------
  // Signed Slack install tokens (shareable, no Eve auth needed to redeem)
  // ---------------------------------------------------------------------------

  private static DEFAULT_INSTALL_TTL_S = 86400; // 24 hours
  private static MAX_INSTALL_TTL_S = 7 * 86400; // 7 days

  generateSlackInstallToken(orgId: string, ttlSeconds?: number): { token: string; expiresAt: string } {
    const secret = platformSigningKeys('slack-install').sign;
    if (!secret) {
      throw new BadRequestException('Internal API key not configured');
    }

    const ttl = Math.min(
      ttlSeconds ?? IntegrationsService.DEFAULT_INSTALL_TTL_S,
      IntegrationsService.MAX_INSTALL_TTL_S,
    );
    const jti = crypto.randomUUID();
    const exp = Math.floor(Date.now() / 1000) + ttl;
    const payload = { org_id: orgId, jti, exp, iat: Math.floor(Date.now() / 1000) };

    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const sig = crypto.createHmac('sha256', secret).update(payloadB64).digest('base64url');
    const token = `eve-slack-install-${payloadB64}.${sig}`;

    return { token, expiresAt: new Date(exp * 1000).toISOString() };
  }

  validateSlackInstallToken(token: string): { orgId: string } | null {
    const secrets = platformSigningKeys('slack-install').verify;
    if (secrets.length === 0) return null;

    const raw = token.startsWith('eve-slack-install-') ? token.slice('eve-slack-install-'.length) : token;
    const dotIdx = raw.lastIndexOf('.');
    if (dotIdx < 0) return null;

    const payloadB64 = raw.slice(0, dotIdx);
    const sig = raw.slice(dotIdx + 1);

    if (!signatureMatches(secrets, payloadB64, sig)) return null;

    let payload: { org_id: string; jti: string; exp: number };
    try {
      payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
    } catch {
      return null;
    }

    if (payload.exp < Math.floor(Date.now() / 1000)) return null;

    if (this.redeemedJtis.has(payload.jti)) return null;
    this.redeemedJtis.add(payload.jti);
    setTimeout(() => this.redeemedJtis.delete(payload.jti), (payload.exp - Math.floor(Date.now() / 1000)) * 1000);

    return { orgId: payload.org_id };
  }
}

/** True when `sig` is the HMAC-SHA256 (base64url) of `payload` under any of the keys. */
function signatureMatches(keys: string[], payload: string, sig: string): boolean {
  const presented = Buffer.from(sig);
  return keys.some((key) => {
    const expected = Buffer.from(crypto.createHmac('sha256', key).update(payload).digest('base64url'));
    return expected.length === presented.length && crypto.timingSafeEqual(expected, presented);
  });
}
