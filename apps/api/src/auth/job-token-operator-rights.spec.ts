import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync } from 'crypto';
import { DEFAULT_AGENT_PERMISSIONS, type SecurityProfile } from '@eve/shared';
import { AccessService } from './access.service';
import { AuthService } from './auth.service';
import { AppAuthService } from './app-auth.service';
import { MagicLinkService } from './magic-link.service';
import { TokenVerifierService } from './token-verifier.service';
import { BootstrapService } from './bootstrap.service';
import { AuthInternalController } from './auth.internal.controller';
import type { SecurityService } from '../security/security.service';
import type { MailerService } from '../mailer/mailer.service';
import type { IdentityProviderRegistry } from './providers/index.js';

/**
 * Rule access.operator_rights (P2-7): under a strict project the default
 * job permissions do not carry jobs:harness_override. A job token keeps it
 * only when the job's agent declares it in access.permissions.
 */

const m = vi.hoisted(() => ({
  jobs: [] as Array<Record<string, unknown>>,
  agent: null as Record<string, unknown> | null,
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    jobQueries: vi.fn(() => ({ findById: vi.fn(async (id: string) => m.jobs.find((j) => j.id === id) ?? null) })),
    projectQueries: vi.fn(() => ({ findById: vi.fn(async () => ({ id: 'proj_shop', org_id: 'org_acme', slug: 'shop' })) })),
    agentQueries: vi.fn(() => ({
      findByProjectAndId: vi.fn(async () => m.agent),
      findByOrgAndSlug: vi.fn(async () => null),
    })),
  };
});

const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

function fakeDb() {
  const tag = (() => Promise.resolve([])) as unknown as Record<string, unknown>;
  tag.json = (v: unknown) => v;
  tag.begin = async (fn: (tx: unknown) => unknown) => fn(tag);
  return tag as never;
}

function controller(profile: SecurityProfile) {
  const db = fakeDb();
  const mailer = { send: vi.fn() } as unknown as MailerService;
  const magicLink = new MagicLinkService({} as never, mailer);
  const appAuth = new AppAuthService({} as never, magicLink);
  const tokenVerifier = new TokenVerifierService(db, appAuth, magicLink);
  const bootstrap = new BootstrapService({} as never, appAuth);
  const auth = new AuthService({} as never, {} as IdentityProviderRegistry, magicLink, appAuth, tokenVerifier, bootstrap);
  const security = { effectiveProfile: vi.fn(async () => profile), decide: vi.fn(async () => profile) } as unknown as SecurityService;
  return new AuthInternalController(auth, db, new AccessService({} as never, db), security);
}

async function mintedPermissions(profile: SecurityProfile): Promise<string[]> {
  const minted = await controller(profile).mintJobToken({ job_id: 'shop-1', permissions: [...DEFAULT_AGENT_PERMISSIONS] });
  return JSON.parse(Buffer.from(minted.access_token.split('.')[1], 'base64url').toString()).permissions;
}

describe('a job token minted with the default agent permissions', () => {
  beforeEach(() => {
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    process.env.EVE_AUTH_ENABLED = 'true';
    process.env.EVE_AUTH_PRIVATE_KEY = privatePem;
    m.jobs = [{ id: 'shop-1', project_id: 'proj_shop', actor_user_id: null, user_secrets_excluded: false, assignee: 'helper', secrets_allowlist: null, target: null }];
    m.agent = { id: 'helper', slug: 'helper', access_json: {} };
  });

  it('loses jobs:harness_override under a strict project', async () => {
    const permissions = await mintedPermissions('strict');
    expect(permissions).not.toContain('jobs:harness_override');
    expect(permissions).toEqual(expect.arrayContaining(['jobs:read', 'jobs:write', 'secrets:read']));
  });

  it("keeps it when the job's agent declares it", async () => {
    m.agent = { id: 'helper', slug: 'helper', access_json: { permissions: ['jobs:harness_override'] } };
    expect(await mintedPermissions('strict')).toContain('jobs:harness_override');
  });

  it('keeps it under audit and legacy', async () => {
    expect(await mintedPermissions('audit')).toContain('jobs:harness_override');
    expect(await mintedPermissions('legacy')).toContain('jobs:harness_override');
  });
});
