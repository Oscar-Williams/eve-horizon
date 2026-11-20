import { createPublicKey, generateKeyPairSync, verify } from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { AuthService } from './auth.service';
import { AppAuthService } from './app-auth.service';
import { MagicLinkService } from './magic-link.service';
import { TokenVerifierService } from './token-verifier.service';
import { BootstrapService } from './bootstrap.service';
import { AuthInternalController } from './auth.internal.controller.js';
import type { MailerService } from '../mailer/mailer.service';
import type { IdentityProviderRegistry } from './providers/index.js';

/**
 * The worker renews service tokens signed by a key the API no longer signs
 * with. It holds no keys, so an internal route names the key the API signs
 * with now: its kid and public key, never a retired one still trusted.
 */

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const empty = () => ({});
  return { ...actual, userQueries: vi.fn(empty), membershipQueries: vi.fn(empty), projectQueries: vi.fn(empty) };
});

const pem = (key: ReturnType<typeof generateKeyPairSync>['privateKey']) =>
  key.export({ type: 'pkcs8', format: 'pem' }).toString();
const signer = generateKeyPairSync('rsa', { modulusLength: 2048 });
const retired = generateKeyPairSync('rsa', { modulusLength: 2048 });

function buildAuthService(): AuthService {
  const mailer = { send: vi.fn() } as unknown as MailerService;
  const magicLink = new MagicLinkService({} as never, mailer);
  const appAuth = new AppAuthService({} as never, magicLink);
  const tokenVerifier = new TokenVerifierService({} as never, appAuth, magicLink);
  const bootstrap = new BootstrapService({} as never, appAuth);
  return new AuthService({} as never, {} as IdentityProviderRegistry, magicLink, appAuth, tokenVerifier, bootstrap);
}

describe('internal signing-key route', () => {
  beforeEach(() => {
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    process.env.EVE_AUTH_ENABLED = 'true';
    process.env.EVE_AUTH_PRIVATE_KEY = pem(signer.privateKey);
    process.env.EVE_AUTH_KEY_ID = 'key-2';
    process.env.EVE_AUTH_PUBLIC_KEY_OLD = retired.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    process.env.EVE_AUTH_KEY_ID_OLD = 'key-1';
  });

  it('names the key the API signs with now', () => {
    const authService = buildAuthService();
    const controller = new AuthInternalController(authService, {} as never, {} as never);

    const key = controller.signingKey();

    expect(key.kid).toBe('key-2');
    const token = authService.mintServiceToken({
      projectId: 'proj_shop',
      orgId: 'org_acme',
      envName: 'prod',
      serviceName: 'api',
      permissions: ['jobs:read'],
    });
    const [header, payload, signature] = token.split('.');
    const publicKey = createPublicKey({ key: key.public_key as never, format: 'jwk' });
    expect(verify('RSA-SHA256', Buffer.from(`${header}.${payload}`), publicKey, Buffer.from(signature, 'base64url')))
      .toBe(true);
    expect(JSON.parse(Buffer.from(header, 'base64url').toString()).kid).toBe(key.kid);
  });
});
