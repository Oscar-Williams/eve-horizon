import { createHmac, generateKeyPairSync } from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { UnauthorizedException } from '@nestjs/common';
import { TokenVerifierService } from './token-verifier.service';
import { createJwtRs256, loadKeyRing } from './auth.util';
import type { AppAuthService } from './app-auth.service';
import type { MagicLinkService } from './magic-link.service';
import { loadConfig } from '@eve/shared';

const SUPABASE_SECRET = 'test-supabase-jwt-secret';
const GOTRUE_ID = '3a0f6c9e-5b1d-4e2a-8c7f-9d0e1f2a3b4c';

const mocks = vi.hoisted(() => ({
  users: {
    findById: vi.fn(),
    findByEmail: vi.fn(),
    create: vi.fn(),
  },
  identities: {
    findByFingerprint: vi.fn(),
    listByUserAndProvider: vi.fn(),
    create: vi.fn(),
  },
  memberships: {
    listOrgMembershipsForUser: vi.fn(),
    upsertOrgMembership: vi.fn(),
  },
  orgInvites: {
    findByIdentityHint: vi.fn(),
    markUsed: vi.fn(),
  },
}));

vi.mock('@eve/db', () => ({
  userQueries: vi.fn(() => mocks.users),
  identityQueries: vi.fn(() => mocks.identities),
  membershipQueries: vi.fn(() => mocks.memberships),
  orgInviteQueries: vi.fn(() => mocks.orgInvites),
  jobQueries: vi.fn(() => ({})),
}));

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

function base64url(value: Record<string, unknown>): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

/** An HS256 token signed with the GoTrue secret, with exactly these claims. */
function hs256(claims: Record<string, unknown>): string {
  const header = base64url({ alg: 'HS256', typ: 'JWT' });
  const now = Math.floor(Date.now() / 1000);
  const payload = base64url({ iat: now, exp: now + 3600, ...claims });
  const signature = createHmac('sha256', SUPABASE_SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}

/** An RS256 token signed with Eve's own key. */
function rs256(claims: Record<string, unknown>): string {
  const key = loadKeyRing(loadConfig()).find((k) => k.privateKey);
  if (!key) throw new Error('test signing key missing');
  const now = Math.floor(Date.now() / 1000);
  return createJwtRs256({ iat: now, exp: now + 3600, ...claims }, key);
}

const eveUser = { id: 'user_known', email: 'person@example.com', is_admin: false, display_name: null };

describe('TokenVerifierService token claims', () => {
  let verifier: TokenVerifierService;

  beforeEach(() => {
    vi.clearAllMocks();
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    process.env.EVE_AUTH_ENABLED = 'true';
    process.env.EVE_AUTH_PRIVATE_KEY = privatePem;
    process.env.SUPABASE_JWT_SECRET = SUPABASE_SECRET;

    mocks.identities.findByFingerprint.mockResolvedValue({ user_id: eveUser.id });
    mocks.identities.listByUserAndProvider.mockResolvedValue([]);
    mocks.identities.create.mockImplementation(async (identity) => identity);
    mocks.users.findById.mockImplementation(async (id: string) => (id === eveUser.id ? eveUser : null));
    mocks.users.findByEmail.mockResolvedValue(null);
    mocks.users.create.mockImplementation(async (user) => user);
    mocks.memberships.listOrgMembershipsForUser.mockResolvedValue([]);
    mocks.orgInvites.findByIdentityHint.mockResolvedValue(null);

    const db = vi.fn(async () => []);
    const magicLink = { emitDomainSignupEvent: vi.fn() } as unknown as MagicLinkService;
    verifier = new TokenVerifierService(db as never, {} as AppAuthService, magicLink);
  });

  describe('HS256 (GoTrue) tokens', () => {
    it('accepts a signed-in user token: aud and role are both "authenticated"', async () => {
      const token = hs256({ sub: GOTRUE_ID, email: eveUser.email, aud: 'authenticated', role: 'authenticated' });
      await expect(verifier.verifyAuthorizationHeader(`Bearer ${token}`)).resolves.toMatchObject({
        user_id: eveUser.id,
      });
    });

    it('refuses a token with a subject and the service_role role', async () => {
      const token = hs256({ sub: GOTRUE_ID, aud: 'authenticated', role: 'service_role' });
      await expect(verifier.verifyAuthorizationHeader(`Bearer ${token}`)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('refuses a token with no audience', async () => {
      const token = hs256({ sub: GOTRUE_ID, email: eveUser.email, role: 'authenticated' });
      await expect(verifier.verifyAuthorizationHeader(`Bearer ${token}`)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('refuses a token with another audience', async () => {
      const token = hs256({ sub: GOTRUE_ID, aud: 'anon', role: 'authenticated' });
      await expect(verifier.verifyAuthorizationHeader(`Bearer ${token}`)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('refuses such tokens at the exchange too, before any user is created or linked', async () => {
      mocks.identities.findByFingerprint.mockResolvedValue(null);
      const token = hs256({ sub: GOTRUE_ID, email: 'new@example.com', role: 'service_role', aud: 'authenticated' });
      await expect(verifier.resolveSupabaseTokenForExchange(token)).rejects.toBeInstanceOf(UnauthorizedException);
      expect(mocks.users.create).not.toHaveBeenCalled();
      expect(mocks.identities.create).not.toHaveBeenCalled();
    });
  });

  describe('RS256 (Eve) tokens', () => {
    it('accepts a user token', async () => {
      const token = rs256({ sub: eveUser.id, type: 'user' });
      await expect(verifier.verifyAuthorizationHeader(`Bearer ${token}`)).resolves.toMatchObject({
        user_id: eveUser.id,
      });
    });

    it('accepts an older user token with no type', async () => {
      const token = rs256({ sub: eveUser.id });
      await expect(verifier.verifyAuthorizationHeader(`Bearer ${token}`)).resolves.toMatchObject({
        user_id: eveUser.id,
      });
    });

    it('refuses a token whose type is not one Eve issues', async () => {
      const token = rs256({ sub: eveUser.id, type: 'foo' });
      await expect(verifier.verifyAuthorizationHeader(`Bearer ${token}`)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });
});
