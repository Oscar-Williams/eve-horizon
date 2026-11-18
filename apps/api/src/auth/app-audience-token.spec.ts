import { generateKeyPairSync } from 'crypto';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { loadConfig } from '@eve/shared';
import { AuthController } from './auth.controller';
import { AuthGuard } from './auth.guard';
import { AuthService } from './auth.service';
import { AppAuthService } from './app-auth.service';
import { MagicLinkService } from './magic-link.service';
import { TokenVerifierService } from './token-verifier.service';
import { BootstrapService } from './bootstrap.service';
import { RbacService } from './rbac.service';
import { createJwtRs256, loadKeyRing } from './auth.util';
import type { MailerService } from '../mailer/mailer.service';
import type { IdentityProviderRegistry } from './providers/index.js';

/**
 * App audience tokens (aud eve-app:<project>[:<env>]) are accepted only on
 * /auth/me, /auth/app-access, /auth/app-invites and /auth/token/verify, with
 * a matching X-Eve-Audience header, and only for the token's own project.
 */

const users = vi.hoisted(() => [
  { id: 'user_visitor', email: 'visitor@example.com', is_admin: true, display_name: null },
]);

const memberships = vi.hoisted(() => [
  { org_id: 'org_h', user_id: 'user_visitor', role: 'admin', created_at: new Date() },
  { org_id: 'org_p', user_id: 'user_visitor', role: 'admin', created_at: new Date() },
]);

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    userQueries: vi.fn(() => ({
      findById: vi.fn(async (id: string) => users.find((u) => u.id === id) ?? null),
      findByEmail: vi.fn(async () => null),
    })),
    membershipQueries: vi.fn(() => ({
      listOrgMembershipsForUser: vi.fn(async (userId: string) => memberships.filter((m) => m.user_id === userId)),
      findProjectMembership: vi.fn(async () => null),
      findOrgMembership: vi.fn(async (userId: string, orgId: string) =>
        memberships.find((m) => m.user_id === userId && m.org_id === orgId) ?? null),
    })),
    projectQueries: vi.fn(() => ({
      findById: vi.fn(async (id: string) => ({ id, org_id: id === 'proj_payroll' ? 'org_p' : 'org_h', slug: id })),
    })),
  };
});

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

const APP_H = 'proj_hostile';
const APP_P = 'proj_payroll';
const AUD_H = `eve-app:${APP_H}:prod`;

function sign(claims: Record<string, unknown>): string {
  const key = loadKeyRing(loadConfig()).find((k) => k.privateKey);
  if (!key) throw new Error('test signing key missing');
  const now = Math.floor(Date.now() / 1000);
  return createJwtRs256({ iat: now, exp: now + 3600, type: 'user', ...claims }, key);
}

/** A token the SSO gave app H for a visitor who is an admin in two orgs. */
function appToken(aud: string = AUD_H): string {
  return sign({ sub: 'user_visitor', email: 'visitor@example.com', aud });
}

function build() {
  const db = vi.fn(async () => []);
  const mailer = { send: vi.fn() } as unknown as MailerService;
  const magicLink = new MagicLinkService(db as never, mailer);
  const appAuth = new AppAuthService(db as never, magicLink);
  const verifier = new TokenVerifierService(db as never, appAuth, magicLink);
  const bootstrap = new BootstrapService(db as never, appAuth);
  const authService = new AuthService(
    db as never,
    {} as IdentityProviderRegistry,
    magicLink,
    appAuth,
    verifier,
    bootstrap,
  );
  const controller = new AuthController(authService, new RbacService(db as never), mailer);
  const guard = new AuthGuard(authService, new Reflector(), { extractFromRequest: () => null } as never);
  return { verifier, controller, guard };
}

function httpContext(handler: (...args: never[]) => unknown, request: Record<string, unknown>): ExecutionContext {
  return {
    getHandler: () => handler,
    getClass: () => AuthController,
    switchToHttp: () => ({ getRequest: () => request }),
  } as unknown as ExecutionContext;
}

describe('app audience tokens', () => {
  beforeEach(() => {
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    process.env.EVE_AUTH_ENABLED = 'true';
    process.env.EVE_AUTH_PRIVATE_KEY = privatePem;
  });

  describe('every other route', () => {
    it('refuses the token on a route that does not take app tokens (for example /projects)', async () => {
      const { guard } = build();
      function listProjects(): void {}
      const request = {
        headers: { authorization: `Bearer ${appToken()}`, 'x-eve-audience': AUD_H },
        query: {},
      };
      await expect(guard.canActivate(httpContext(listProjects, request))).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('refuses the token wherever it is verified without app audience context', async () => {
      const { verifier } = build();
      await expect(verifier.verifyAuthorizationHeader(`Bearer ${appToken()}`)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('refuses a user token whose audience is not an app audience', async () => {
      const { controller } = build();
      const token = sign({ sub: 'user_visitor', aud: 'eve-registry' });
      await expect(controller.me(`Bearer ${token}`, undefined, 'eve-registry')).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });
  });

  describe('GET /auth/me', () => {
    it('refuses the token without the X-Eve-Audience header', async () => {
      const { controller } = build();
      await expect(controller.me(`Bearer ${appToken()}`, undefined, undefined)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('refuses the token when the header names another audience', async () => {
      const { controller } = build();
      await expect(
        controller.me(`Bearer ${appToken()}`, undefined, `eve-app:${APP_P}:prod`),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('refuses the token when the request names another project', async () => {
      const { controller } = build();
      await expect(controller.me(`Bearer ${appToken()}`, APP_P, AUD_H)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('accepts the token with the matching header, and answers with the live memberships', async () => {
      const { controller } = build();
      const me = await controller.me(`Bearer ${appToken()}`, undefined, AUD_H);
      expect(me).toMatchObject({
        authenticated: true,
        type: 'user',
        user_id: 'user_visitor',
        is_admin: true,
      });
      expect(me.memberships?.map((m) => m.org_id).sort()).toEqual(['org_h', 'org_p']);
    });
  });

  describe('GET /auth/token/verify', () => {
    it('refuses the token without the header', async () => {
      const { controller } = build();
      await expect(controller.tokenVerify(`Bearer ${appToken()}`, undefined)).rejects.toBeInstanceOf(
        UnauthorizedException,
      );
    });

    it('accepts the token with the matching header', async () => {
      const { controller } = build();
      await expect(controller.tokenVerify(`Bearer ${appToken()}`, AUD_H)).resolves.toMatchObject({
        valid: true,
        type: 'user',
        user_id: 'user_visitor',
      });
    });
  });

  describe('POST /auth/app-invites', () => {
    it("refuses app H's token for project P, even with H's own header", async () => {
      const { guard } = build();
      const request = {
        headers: { authorization: `Bearer ${appToken()}`, 'x-eve-audience': AUD_H },
        query: {},
        body: { project_id: APP_P, org_id: 'org_p', email: 'new@example.com' },
      };
      await expect(
        guard.canActivate(httpContext(AuthController.prototype.createAppInvite, request)),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it("lets app H's token through for project H with H's header", async () => {
      const { guard } = build();
      const request: Record<string, unknown> = {
        headers: { authorization: `Bearer ${appToken()}`, 'x-eve-audience': AUD_H },
        query: {},
        body: { project_id: APP_H, org_id: 'org_h', email: 'new@example.com' },
      };
      await expect(
        guard.canActivate(httpContext(AuthController.prototype.createAppInvite, request)),
      ).resolves.toBe(true);
      expect(request.user).toMatchObject({ user_id: 'user_visitor' });
    });
  });

  describe('GET /auth/app-access', () => {
    it('refuses the token for another project', async () => {
      const { guard } = build();
      const request = {
        headers: { authorization: `Bearer ${appToken()}`, 'x-eve-audience': AUD_H },
        query: { project_id: APP_P },
      };
      await expect(
        guard.canActivate(httpContext(AuthController.prototype.getAppAccess, request)),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it('refuses the token without the header', async () => {
      const { guard } = build();
      const request = {
        headers: { authorization: `Bearer ${appToken()}` },
        query: { project_id: APP_H },
      };
      await expect(
        guard.canActivate(httpContext(AuthController.prototype.getAppAccess, request)),
      ).rejects.toBeInstanceOf(UnauthorizedException);
    });

    it("accepts the token for the app's own project with the header", async () => {
      const { guard } = build();
      const request = {
        headers: { authorization: `Bearer ${appToken()}`, 'x-eve-audience': AUD_H },
        query: { project_id: APP_H },
      };
      await expect(
        guard.canActivate(httpContext(AuthController.prototype.getAppAccess, request)),
      ).resolves.toBe(true);
    });
  });

  describe('full user tokens', () => {
    it('are unchanged: accepted on any route without the header', async () => {
      const { guard } = build();
      function listProjects(): void {}
      const token = sign({ sub: 'user_visitor', orgs: [] });
      const request = { headers: { authorization: `Bearer ${token}` }, query: {} };
      await expect(guard.canActivate(httpContext(listProjects, request))).resolves.toBe(true);
    });
  });
});
