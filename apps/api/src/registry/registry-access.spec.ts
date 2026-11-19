import { generateKeyPairSync } from 'crypto';
import { UnauthorizedException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mintRegistryPullCredential, mintRegistryPushCredential, type SecurityProfile } from '@eve/shared';
import {
  grantRegistryAccess,
  identifyRegistryCaller,
  isPullCredentialCurrent,
} from './registry-access.js';
import { RegistryTokenController } from './registry-token.controller.js';

const KEY = 'internal-key';
const CREDENTIAL_KEY = 'registry-credential-key';
const PROJECT = 'proj_01hshop';
const PULL_CLAIMS = { projectId: PROJECT, environmentId: 'env_test', namespace: 'eve-acme-shop-test', epoch: 4 };
const projectCaller = { kind: 'project-pull' as const, ...PULL_CLAIMS };
const pushCaller = { kind: 'project-push' as const, projectId: PROJECT, expiresAt: 9_999_999_999 };

/** SecurityService.decide under one instance profile, recording each finding. */
function fakeSecurity(profile: SecurityProfile) {
  const findings: Array<{ rule: string; ctx: Record<string, unknown> }> = [];
  return {
    findings,
    profile,
    decide: vi.fn(async function (this: { profile: SecurityProfile }, rule: string, ctx: Record<string, unknown>) {
      if (this.profile !== 'legacy') findings.push({ rule, ctx });
      return this.profile;
    }),
  };
}

describe('identifyRegistryCaller', () => {
  const internalOnly = { internalKey: KEY };
  const both = { credentialKey: CREDENTIAL_KEY, internalKey: KEY };

  it('recognises the internal key, as a credential signed with the internal key', () => {
    expect(identifyRegistryCaller(KEY, internalOnly)).toEqual({ caller: { kind: 'internal' }, key: 'internal' });
    expect(identifyRegistryCaller(KEY, both)).toEqual({ caller: { kind: 'internal' }, key: 'internal' });
  });

  it('recognises a pull credential, and which key signed it', () => {
    expect(identifyRegistryCaller(mintRegistryPullCredential(PULL_CLAIMS, KEY), internalOnly))
      .toEqual({ caller: projectCaller, key: 'internal' });
    expect(identifyRegistryCaller(mintRegistryPullCredential(PULL_CLAIMS, KEY), both))
      .toEqual({ caller: projectCaller, key: 'internal' });
    expect(identifyRegistryCaller(mintRegistryPullCredential(PULL_CLAIMS, CREDENTIAL_KEY), both))
      .toEqual({ caller: projectCaller, key: 'credential' });
  });

  it('recognises an unexpired push credential', () => {
    expect(identifyRegistryCaller(mintRegistryPushCredential(PROJECT, CREDENTIAL_KEY), both)).toMatchObject({
      caller: { kind: 'project-push', projectId: PROJECT },
      key: 'credential',
    });
    const expired = mintRegistryPushCredential(PROJECT, CREDENTIAL_KEY, 1_000);
    expect(identifyRegistryCaller(expired, both)).toBeNull();
  });

  it('rejects anything else, and everything when no key is configured', () => {
    expect(identifyRegistryCaller('wrong', both)).toBeNull();
    expect(identifyRegistryCaller(undefined, both)).toBeNull();
    expect(identifyRegistryCaller(KEY, {})).toBeNull();
    expect(identifyRegistryCaller(CREDENTIAL_KEY, both)).toBeNull();
    expect(identifyRegistryCaller(mintRegistryPullCredential(PULL_CLAIMS, 'other-key'), both)).toBeNull();
    // Once the internal key is removed, credentials it signed no longer verify.
    expect(identifyRegistryCaller(mintRegistryPullCredential(PULL_CLAIMS, KEY), { credentialKey: CREDENTIAL_KEY })).toBeNull();
  });
});

describe('isPullCredentialCurrent', () => {
  const liveEnv = { project_id: PROJECT, status: 'active', registry_pull_epoch: 4 };

  it('honours the current epoch and the one before it', () => {
    expect(isPullCredentialCurrent(projectCaller, liveEnv, true)).toBe(true);
    expect(isPullCredentialCurrent(projectCaller, { ...liveEnv, registry_pull_epoch: 5 }, true)).toBe(true);
    expect(isPullCredentialCurrent(projectCaller, { ...liveEnv, status: 'suspended' }, true)).toBe(true);
  });

  it('refuses a superseded credential (two rewrites later) or one from the future', () => {
    expect(isPullCredentialCurrent(projectCaller, { ...liveEnv, registry_pull_epoch: 6 }, true)).toBe(false);
    expect(isPullCredentialCurrent(projectCaller, { ...liveEnv, registry_pull_epoch: 3 }, true)).toBe(false);
  });

  it('refuses a deleted or terminated environment, another project, or a deleted project', () => {
    expect(isPullCredentialCurrent(projectCaller, null, true)).toBe(false);
    expect(isPullCredentialCurrent(projectCaller, { ...liveEnv, status: 'terminated' }, true)).toBe(false);
    expect(isPullCredentialCurrent(projectCaller, { ...liveEnv, project_id: 'proj_other' }, true)).toBe(false);
    expect(isPullCredentialCurrent(projectCaller, liveEnv, false)).toBe(false);
  });
});

describe('grantRegistryAccess', () => {
  const requested = [
    { type: 'repository', name: `${PROJECT}/api`, actions: ['pull', 'push'] },
    { type: 'repository', name: `${PROJECT}/acme/web`, actions: ['pull'] },
    { type: 'repository', name: 'proj_01hvictim/api', actions: ['pull', 'push'] },
    { type: 'repository', name: 'api', actions: ['pull'] },
    { type: 'repository', name: `${PROJECT}-evil/api`, actions: ['pull'] },
    { type: 'repository', name: `${PROJECT}/api`, actions: ['delete', '*'] },
    { type: 'registry', name: 'catalog', actions: ['*'] },
  ];

  it('gives internal callers push and pull on any repository, nothing else', () => {
    expect(grantRegistryAccess({ kind: 'internal' }, requested)).toEqual([
      { type: 'repository', name: `${PROJECT}/api`, actions: ['pull', 'push'] },
      { type: 'repository', name: `${PROJECT}/acme/web`, actions: ['pull'] },
      { type: 'repository', name: 'proj_01hvictim/api', actions: ['pull', 'push'] },
      { type: 'repository', name: 'api', actions: ['pull'] },
      { type: 'repository', name: `${PROJECT}-evil/api`, actions: ['pull'] },
    ]);
  });

  it('gives a build push and pull under its project prefix only', () => {
    expect(grantRegistryAccess(pushCaller, requested)).toEqual([
      { type: 'repository', name: `${PROJECT}/api`, actions: ['pull', 'push'] },
      { type: 'repository', name: `${PROJECT}/acme/web`, actions: ['pull'] },
    ]);
  });

  it('gives an environment pull only, under its project prefix only', () => {
    expect(grantRegistryAccess(projectCaller, requested)).toEqual([
      { type: 'repository', name: `${PROJECT}/api`, actions: ['pull'] },
      { type: 'repository', name: `${PROJECT}/acme/web`, actions: ['pull'] },
    ]);
  });
});

describe('RegistryTokenController GET /internal/registry/token', () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const signingKey = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();

  function basic(username: string, password: string): string {
    return `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  }

  function payloadOf(token: string): { access: unknown; sub: string } {
    return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8'));
  }

  let controller: RegistryTokenController;
  let security: ReturnType<typeof fakeSecurity>;
  let environment: { project_id: string; status: string; registry_pull_epoch: number } | null;
  let project: { id: string } | null;
  const pullCredential = () => mintRegistryPullCredential(PULL_CLAIMS, KEY);

  beforeEach(() => {
    vi.stubEnv('DATABASE_URL', 'postgres://user:pass@localhost:5432/eve_test');
    vi.stubEnv('EVE_INTERNAL_API_KEY', KEY);
    vi.stubEnv('EVE_REGISTRY_SIGNING_KEY', signingKey);
    environment = { project_id: PROJECT, status: 'active', registry_pull_epoch: 4 };
    project = { id: PROJECT };
    security = fakeSecurity('legacy');
    controller = new RegistryTokenController(null as any, security as any);
    (controller as any).environments = { findById: vi.fn(async (id: string) => (id === 'env_test' ? environment : null)) };
    (controller as any).projects = { findById: vi.fn(async (id: string) => (id === PROJECT ? project : null)) };
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('grants an environment pull credential pull under its project prefix only', async () => {
    const response = await controller.issueTokenGet(
      basic('eve-pull', pullCredential()),
      [`repository:${PROJECT}/api:pull,push`, 'repository:proj_01hvictim/api:pull', 'repository:api:pull'],
      'eve-registry',
    );
    const payload = payloadOf(response.token);
    expect(payload.access).toEqual([{ type: 'repository', name: `${PROJECT}/api`, actions: ['pull'] }]);
    expect(payload.sub).toBe(`eve-pull:${PROJECT}`);
  });

  it('grants a build push and pull under its project prefix only', async () => {
    const response = await controller.issueTokenGet(
      basic('eve-push', mintRegistryPushCredential(PROJECT, KEY)),
      [`repository:${PROJECT}/api:pull,push`, 'repository:proj_01hvictim/api:pull,push'],
      'eve-registry',
    );
    const payload = payloadOf(response.token);
    expect(payload.access).toEqual([{ type: 'repository', name: `${PROJECT}/api`, actions: ['pull', 'push'] }]);
    expect(payload.sub).toBe(`eve-push:${PROJECT}`);
  });

  it('refuses a pull credential once its environment is deleted, terminated or redeployed twice', async () => {
    const attempt = () =>
      controller.issueTokenGet(basic('eve-pull', pullCredential()), `repository:${PROJECT}/api:pull`, 'eve-registry');

    environment = null;
    await expect(attempt()).rejects.toThrow(UnauthorizedException);
    environment = { project_id: PROJECT, status: 'terminated', registry_pull_epoch: 4 };
    await expect(attempt()).rejects.toThrow(UnauthorizedException);
    environment = { project_id: PROJECT, status: 'active', registry_pull_epoch: 6 };
    await expect(attempt()).rejects.toThrow(UnauthorizedException);
    environment = { project_id: PROJECT, status: 'active', registry_pull_epoch: 4 };
    project = null;
    await expect(attempt()).rejects.toThrow(UnauthorizedException);
  });

  it('answers a scopeless login probe with an empty token', async () => {
    const response = await controller.issueTokenGet(basic('eve-pull', pullCredential()), undefined, 'eve-registry');
    expect(payloadOf(response.token).access).toEqual([]);
  });

  it('rejects unknown and expired credentials', async () => {
    await expect(
      controller.issueTokenGet(basic('eve-pull', 'not-a-credential'), 'repository:api:pull', 'eve-registry'),
    ).rejects.toThrow(UnauthorizedException);
    await expect(
      controller.issueTokenGet(
        basic('eve-push', mintRegistryPushCredential(PROJECT, KEY, 1_000)),
        `repository:${PROJECT}/api:push`,
        'eve-registry',
      ),
    ).rejects.toThrow(UnauthorizedException);
    await expect(controller.issueTokenGet(undefined, 'repository:api:pull', 'eve-registry')).rejects.toThrow(
      UnauthorizedException,
    );
  });

  it('limits the internal POST endpoint to push and pull on repositories', async () => {
    const response = await controller.issueToken({
      scope: ['repository:shop-api:push,pull,delete', 'registry:catalog:*'],
      service: 'eve-registry',
    });
    expect(payloadOf(response.token).access).toEqual([
      { type: 'repository', name: 'shop-api', actions: ['push', 'pull'] },
    ]);
  });
});

describe('registry.internal_key: the internal key and credentials it signed', () => {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const signingKey = privateKey.export({ format: 'pem', type: 'pkcs8' }).toString();
  const basic = (username: string, password: string) =>
    `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`;
  let security: ReturnType<typeof fakeSecurity>;
  let controller: RegistryTokenController;

  function under(profile: SecurityProfile) {
    security = fakeSecurity(profile);
    controller = new RegistryTokenController(null as any, security as any);
    (controller as any).environments = {
      findById: vi.fn(async () => ({ project_id: PROJECT, status: 'active', registry_pull_epoch: 4 })),
    };
    (controller as any).projects = { findById: vi.fn(async () => ({ id: PROJECT })) };
  }

  const pullWith = (key: string) => basic('eve-pull', mintRegistryPullCredential(PULL_CLAIMS, key));
  const pushWith = (key: string) => basic('eve-push', mintRegistryPushCredential(PROJECT, key));
  const scope = `repository:${PROJECT}/api:pull`;

  beforeEach(() => {
    vi.stubEnv('DATABASE_URL', 'postgres://user:pass@localhost:5432/eve_test');
    vi.stubEnv('EVE_INTERNAL_API_KEY', KEY);
    vi.stubEnv('EVE_REGISTRY_CREDENTIAL_KEY', CREDENTIAL_KEY);
    vi.stubEnv('EVE_REGISTRY_SIGNING_KEY', signingKey);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('under strict, a Basic internal key gets 401', async () => {
    under('strict');
    await expect(controller.issueTokenGet(basic('eve', KEY), scope, 'eve-registry')).rejects.toThrow(UnauthorizedException);
    expect(security.findings).toEqual([
      expect.objectContaining({ rule: 'registry.internal_key', ctx: expect.objectContaining({ governing: 'instance' }) }),
    ]);
  });

  it('under strict, pull and push credentials signed with the internal key get 401', async () => {
    under('strict');
    await expect(controller.issueTokenGet(pullWith(KEY), scope, 'eve-registry')).rejects.toThrow(UnauthorizedException);
    await expect(controller.issueTokenGet(pushWith(KEY), scope, 'eve-registry')).rejects.toThrow(UnauthorizedException);
    expect(security.findings.map((f) => f.rule)).toEqual(['registry.internal_key', 'registry.internal_key']);
    expect(security.findings[0].ctx).toMatchObject({ projectId: PROJECT, detail: { caller: 'project-pull' } });
  });

  it('under strict, credentials signed with the registry credential key work, with no finding', async () => {
    under('strict');
    await expect(controller.issueTokenGet(pullWith(CREDENTIAL_KEY), scope, 'eve-registry')).resolves.toHaveProperty('token');
    await expect(controller.issueTokenGet(pushWith(CREDENTIAL_KEY), scope, 'eve-registry')).resolves.toHaveProperty('token');
    expect(security.findings).toEqual([]);
  });

  it('under audit, both signatures and the internal key work, and the old ones are recorded', async () => {
    under('audit');
    await expect(controller.issueTokenGet(pullWith(KEY), scope, 'eve-registry')).resolves.toHaveProperty('token');
    await expect(controller.issueTokenGet(basic('eve', KEY), scope, 'eve-registry')).resolves.toHaveProperty('token');
    await expect(controller.issueTokenGet(pullWith(CREDENTIAL_KEY), scope, 'eve-registry')).resolves.toHaveProperty('token');
    expect(security.findings.map((f) => f.rule)).toEqual(['registry.internal_key', 'registry.internal_key']);
  });

  it('records nothing for a stale credential it refuses anyway', async () => {
    under('audit');
    (controller as any).environments = {
      findById: vi.fn(async () => ({ project_id: PROJECT, status: 'terminated', registry_pull_epoch: 4 })),
    };
    await expect(controller.issueTokenGet(pullWith(KEY), scope, 'eve-registry')).rejects.toThrow(UnauthorizedException);
    expect(security.findings).toEqual([]);
  });
});
