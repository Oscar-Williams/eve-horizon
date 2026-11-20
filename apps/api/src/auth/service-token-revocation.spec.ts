import { generateKeyPairSync } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { UnauthorizedException } from '@nestjs/common';
import { loadConfig } from '@eve/shared';
import { TokenVerifierService } from './token-verifier.service';
import { createJwtRs256, loadKeyRing } from './auth.util';
import type { AppAuthService } from './app-auth.service';
import type { MagicLinkService } from './magic-link.service';

/**
 * A service token can be revoked: the API refuses one issued before its
 * environment's `service_tokens_not_before`, or one whose environment no
 * longer exists. App-link tokens injected into a service (principal
 * `service:<name>`) follow the same rule for the consumer environment. The
 * environment is looked up at most once a minute.
 */

const mocks = vi.hoisted(() => ({
  environments: { findByProjectAndName: vi.fn() },
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const empty = () => ({});
  return {
    ...actual,
    userQueries: vi.fn(empty),
    identityQueries: vi.fn(empty),
    membershipQueries: vi.fn(empty),
    orgInviteQueries: vi.fn(empty),
    jobQueries: vi.fn(empty),
    environmentQueries: vi.fn(() => mocks.environments),
  };
});

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

const NOW = Date.UTC(2026, 10, 20, 12, 0, 0);
const seconds = (ms: number) => Math.floor(ms / 1000);

function sign(claims: Record<string, unknown>): string {
  const key = loadKeyRing(loadConfig()).find((k) => k.privateKey);
  if (!key) throw new Error('test signing key missing');
  return createJwtRs256({ exp: seconds(NOW) + 3600, ...claims }, key);
}

function serviceToken(issuedAt: number): string {
  return sign({
    sub: 'service:web',
    org_id: 'org_acme',
    project_id: 'proj_shop',
    env_name: 'prod',
    service_name: 'web',
    permissions: ['jobs:read'],
    iat: issuedAt,
    type: 'service',
  });
}

function environment(notBefore: Date | null) {
  return { id: 'env_prod', project_id: 'proj_shop', name: 'prod', service_tokens_not_before: notBefore };
}

const appLinkPayload = (issuedAt: number, principal = 'service:web') => ({
  sub: 'app_link:sub_1',
  subscription_id: 'sub_1',
  consumer_project_id: 'proj_shop',
  consumer_org_id: 'org_acme',
  consumer_principal: principal,
  consumer_env: 'prod',
  producer_project_id: 'proj_ledger',
  producer_env: 'prod',
  api_name: 'ledger',
  scopes: ['read'],
  aud: 'project:proj_ledger',
  exp: seconds(NOW) + 3600,
  iat: issuedAt,
  type: 'app_link',
});

describe('service token revocation', () => {
  let verifier: TokenVerifierService;
  let appAuth: { verifyAppLinkToken: ReturnType<typeof vi.fn> };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    process.env.EVE_AUTH_ENABLED = 'true';
    process.env.EVE_AUTH_PRIVATE_KEY = privatePem;
    appAuth = { verifyAppLinkToken: vi.fn() };
    verifier = new TokenVerifierService(
      {} as never,
      appAuth as unknown as AppAuthService,
      {} as MagicLinkService,
    );
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('refuses a service token issued before its environment\'s service_tokens_not_before', async () => {
    mocks.environments.findByProjectAndName.mockResolvedValue(environment(new Date(NOW - 60_000)));

    await expect(verifier.verifyAuthorizationHeader(`Bearer ${serviceToken(seconds(NOW) - 120)}`))
      .rejects.toThrow(UnauthorizedException);
    expect(mocks.environments.findByProjectAndName).toHaveBeenCalledWith('proj_shop', 'prod');
  });

  it('accepts one issued at or after it', async () => {
    mocks.environments.findByProjectAndName.mockResolvedValue(environment(new Date(NOW - 60_000)));

    const user = await verifier.verifyAuthorizationHeader(`Bearer ${serviceToken(seconds(NOW) - 60)}`);

    expect(user).toMatchObject({ is_service_token: true, project_id: 'proj_shop', env_name: 'prod' });
  });

  it('refuses a service token whose environment no longer exists', async () => {
    mocks.environments.findByProjectAndName.mockResolvedValue(null);

    await expect(verifier.verifyAuthorizationHeader(`Bearer ${serviceToken(seconds(NOW) - 60)}`))
      .rejects.toThrow(UnauthorizedException);
  });

  it('refuses an app-link token injected into a service before the consumer environment\'s floor', async () => {
    mocks.environments.findByProjectAndName.mockResolvedValue(environment(new Date(NOW - 60_000)));
    appAuth.verifyAppLinkToken.mockResolvedValue(appLinkPayload(seconds(NOW) - 120));

    await expect(verifier.verifyAuthorizationHeader(`Bearer ${sign(appLinkPayload(seconds(NOW) - 120))}`))
      .rejects.toThrow(UnauthorizedException);
    expect(mocks.environments.findByProjectAndName).toHaveBeenCalledWith('proj_shop', 'prod');
  });

  it('leaves a job\'s app-link token to the job\'s own liveness', async () => {
    const payload = appLinkPayload(seconds(NOW) - 120, 'job:shop-1a2b3c4d');
    appAuth.verifyAppLinkToken.mockResolvedValue(payload);

    const user = await verifier.verifyAuthorizationHeader(`Bearer ${sign(payload)}`);

    expect(user).toMatchObject({ is_app_link_token: true });
    expect(mocks.environments.findByProjectAndName).not.toHaveBeenCalled();
  });

  it('looks the environment up at most once a minute', async () => {
    mocks.environments.findByProjectAndName.mockResolvedValue(environment(null));
    const token = serviceToken(seconds(NOW) - 60);

    await verifier.verifyAuthorizationHeader(`Bearer ${token}`);
    vi.setSystemTime(NOW + 59_000);
    await verifier.verifyAuthorizationHeader(`Bearer ${token}`);
    expect(mocks.environments.findByProjectAndName).toHaveBeenCalledTimes(1);

    vi.setSystemTime(NOW + 61_000);
    await verifier.verifyAuthorizationHeader(`Bearer ${token}`);
    expect(mocks.environments.findByProjectAndName).toHaveBeenCalledTimes(2);
  });
});
