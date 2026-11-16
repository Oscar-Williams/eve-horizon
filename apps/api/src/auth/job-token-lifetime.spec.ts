import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync } from 'crypto';
import { UnauthorizedException } from '@nestjs/common';
import { AccessService } from './access.service';
import { AuthService } from './auth.service';
import { AppAuthService } from './app-auth.service';
import { MagicLinkService } from './magic-link.service';
import { TokenVerifierService } from './token-verifier.service';
import { BootstrapService } from './bootstrap.service';
import { AuthInternalController } from './auth.internal.controller';
import { AuthController } from './auth.controller';
import type { MailerService } from '../mailer/mailer.service';
import type { IdentityProviderRegistry } from './providers/index.js';

/**
 * opps-1: the engine's triage job, running as attempt att-run-1, with one app
 * link (alias "opps") to the engine's API in project proj_engine.
 */
const m = vi.hoisted(() => {
  const state = {
    job: null as Record<string, unknown> | null,
    runningAttemptId: null as string | null,
  };
  return {
    state,
    jobs: {
      findById: vi.fn(async (id: string) => (state.job && state.job.id === id ? { ...state.job } : null)),
      getCurrentAttempt: vi.fn(async (jobId: string) =>
        state.job && state.job.id === jobId && state.runningAttemptId ? { id: state.runningAttemptId, job_id: jobId, status: 'running' } : null),
    },
    projects: {
      findById: vi.fn(async (id: string) => ({ proj_opps: { id: 'proj_opps', org_id: 'org_vdb' }, proj_engine: { id: 'proj_engine', org_id: 'org_vdb' } } as Record<string, unknown>)[id] ?? null),
    },
    subscriptions: {
      findWithGrantsById: vi.fn(async (id: string) => (id === 'als_opps' ? {
        id: 'als_opps',
        consumer_project_id: 'proj_opps',
        producer_env_name: 'prod',
        requested_scopes: ['notices:read'],
        api_grant: { producer_project_id: 'proj_engine', export_name: 'opps', envs: [], revoked_at: null },
      } : null)),
      recordTokenMint: vi.fn(async () => undefined),
    },
    agents: { findByProjectAndId: vi.fn(async () => null) },
    memberships: {
      findProjectMembership: vi.fn(async () => null),
      findOrgMembership: vi.fn(async () => null),
      listOrgMembershipsForUser: vi.fn(async () => []),
    },
    accessRoles: {
      listApplicableBindings: vi.fn(async () => []),
      getEffectiveCustomPermissions: vi.fn(async () => []),
    },
  };
});

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  jobQueries: vi.fn(() => m.jobs),
  projectQueries: vi.fn(() => m.projects),
  appLinkSubscriptionQueries: vi.fn(() => m.subscriptions),
  agentQueries: vi.fn(() => m.agents),
  membershipQueries: vi.fn(() => m.memberships),
  accessRoleQueries: vi.fn(() => m.accessRoles),
}));

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

function fakeDb() {
  const tag = (() => Promise.resolve([])) as unknown as Record<string, unknown>;
  tag.json = (v: unknown) => v;
  tag.begin = async (fn: (tx: unknown) => unknown) => fn(tag);
  return tag as never;
}

function buildAuth(): { authService: AuthService; internal: AuthInternalController; me: AuthController } {
  const db = fakeDb();
  const mailer = { send: vi.fn() } as unknown as MailerService;
  const magicLink = new MagicLinkService({} as never, mailer);
  const appAuth = new AppAuthService(db, magicLink);
  const tokenVerifier = new TokenVerifierService(db, appAuth, magicLink);
  const bootstrap = new BootstrapService({} as never, appAuth);
  const authService = new AuthService({} as never, {} as IdentityProviderRegistry, magicLink, appAuth, tokenVerifier, bootstrap);
  const internal = new AuthInternalController(authService, db, new AccessService({} as never, db));
  return {
    authService,
    internal,
    me: new AuthController(authService, {} as never, {} as never),
  };
}

function runningJob(phase = 'active') {
  m.state.job = {
    id: 'opps-1', project_id: 'proj_opps', phase, actor_user_id: null, user_secrets_excluded: false,
    assignee: 'triage', secrets_allowlist: null, target: null,
    hints: {
      resolved_app_links: [
        { name: 'opps', alias: 'opps', subscription_id: 'als_opps', producer_project_id: 'proj_engine', producer_env: 'prod', base_url: 'https://opps.example' },
      ],
    },
  };
  m.state.runningAttemptId = 'att-run-1';
}

function claims(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

beforeEach(() => {
  vi.clearAllMocks();
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  process.env.EVE_AUTH_ENABLED = 'true';
  process.env.EVE_AUTH_PRIVATE_KEY = privatePem;
  runningJob();
});

describe('a job token', () => {
  async function mintForAttempt(internal: AuthInternalController): Promise<string> {
    const minted = await (internal.mintJobToken as (body: unknown) => Promise<{ access_token: string }>)(
      { job_id: 'opps-1', permissions: ['jobs:read'], attempt_id: 'att-run-1' },
    );
    return minted.access_token;
  }

  it('is bound to the attempt it was minted for', async () => {
    const { internal } = buildAuth();
    expect(claims(await mintForAttempt(internal)).attempt_id).toBe('att-run-1');
  });

  it("is refused for an attempt that is not the job's running attempt", async () => {
    const { internal } = buildAuth();
    m.state.runningAttemptId = 'att-run-2';
    await expect(mintForAttempt(internal)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('is accepted while its attempt runs and refused once the attempt ends', async () => {
    const { internal, authService } = buildAuth();
    const token = await mintForAttempt(internal);

    await expect(authService.verifyAuthorizationHeader(`Bearer ${token}`)).resolves.toMatchObject({ job_id: 'opps-1' });

    m.state.runningAttemptId = null;
    await expect(authService.verifyAuthorizationHeader(`Bearer ${token}`)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('is refused once the job is cancelled, even before the attempt is recorded as ended', async () => {
    const { internal, authService } = buildAuth();
    const token = await mintForAttempt(internal);

    m.state.job = { ...m.state.job!, phase: 'cancelled' };
    await expect(authService.verifyAuthorizationHeader(`Bearer ${token}`)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('without an attempt is refused once the job is done', async () => {
    const { internal, authService } = buildAuth();
    const { access_token } = await internal.mintJobToken({ job_id: 'opps-1', permissions: ['jobs:read'] });

    await expect(authService.verifyAuthorizationHeader(`Bearer ${access_token}`)).resolves.toMatchObject({ job_id: 'opps-1' });

    m.state.job = { ...m.state.job!, phase: 'done' };
    m.state.runningAttemptId = null;
    await expect(authService.verifyAuthorizationHeader(`Bearer ${access_token}`)).rejects.toBeInstanceOf(UnauthorizedException);
  });
});

describe("a job's app-link token", () => {
  async function mintLinkToken(internal: AuthInternalController): Promise<string> {
    const minted = await (internal.mintAppLinkToken as (body: unknown) => Promise<{ access_token: string }>)(
      { subscription_id: 'als_opps', consumer_principal: 'job:opps-1', producer_env: 'prod', attempt_id: 'att-run-1' },
    );
    return minted.access_token;
  }

  it("lets the producer read the consumer project from /auth/me while the job's attempt runs", async () => {
    const { internal, me } = buildAuth();
    const token = await mintLinkToken(internal);

    await expect(me.me(`Bearer ${token}`)).resolves.toMatchObject({
      type: 'app_link', consumer_project_id: 'proj_opps', consumer_principal: 'job:opps-1',
    });
  });

  it('is refused once the attempt it was minted for ends', async () => {
    const { internal, me } = buildAuth();
    const token = await mintLinkToken(internal);

    m.state.runningAttemptId = null;
    await expect(me.me(`Bearer ${token}`)).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('is refused once the job is done, when minted without an attempt', async () => {
    const { internal, me } = buildAuth();
    const { access_token } = await internal.mintAppLinkToken({ subscription_id: 'als_opps', consumer_principal: 'job:opps-1', producer_env: 'prod' });

    m.state.job = { ...m.state.job!, phase: 'done' };
    m.state.runningAttemptId = null;
    await expect(me.me(`Bearer ${access_token}`)).rejects.toBeInstanceOf(UnauthorizedException);
  });
});
