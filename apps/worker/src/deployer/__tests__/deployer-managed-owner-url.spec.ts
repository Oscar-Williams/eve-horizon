import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import yaml from 'yaml';
import { DeployerService } from '../deployer.service.js';
import { ImageResolver } from '../image-resolver.js';

// Rule managed_db.owner_url: the managed database's owner credential
// (${managed.<db>.url} and .password) reaches only job services, which run
// migrations. Under `strict` a long-running service that reads it is refused
// and must use a declared role; under `audit` each such service is recorded.

const mocks = vi.hoisted(() => ({
  profile: 'legacy' as 'legacy' | 'audit' | 'strict',
  decide: vi.fn(),
  governing: vi.fn(),
  config: {} as Record<string, unknown>,
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: mocks.decide,
  governingSecurityProfile: mocks.governing,
}));

vi.mock('@eve/shared', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    loadConfig: () => ({
      EVE_API_URL: 'http://api.eve.test',
      EVE_DEFAULT_DOMAIN: '',
      EVE_TCP_INGRESS_PROVIDER: 'none',
      EVE_COMPUTE_MODEL: 'k3s',
      ...mocks.config,
    }),
    resolveProjectSecrets: vi.fn(async () => ({ resolved: true, secrets: [], error: null })),
    mintServiceToken: vi.fn(async () => ({ access_token: 'svc-token' })),
  };
});

const params = {
  namespace: 'eve-acme-shop-prod',
  envId: 'env_prod',
  envName: 'prod',
  projectSlug: 'shop',
  projectId: 'proj_shop',
  orgId: 'org_acme',
  orgSlug: 'acme',
  releaseId: 'rel_1',
};

/** Image config `User` per image, as `crane config` would report it; absent: unreadable. */
let imageUsers: Record<string, string> = {};

function newDeployer(k8s: unknown = null) {
  const deployer = new DeployerService(null as any, k8s as any);
  (deployer as any).logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
  // egress.default_deny has its own spec (deployer-egress-policy.spec.ts).
  (deployer as any).egress = { applyEnv: vi.fn(async () => ({})), applyRunners: vi.fn(async () => ({})) };
  const readImageConfig = vi.fn(async (image: string) => (image in imageUsers ? { user: imageUsers[image] } : null));
  (deployer as any).imageResolver.readImageConfig = readImageConfig;
  return { deployer, readImageConfig };
}

async function render(services: Record<string, unknown>, profile = mocks.profile) {
  const { deployer, readImageConfig } = newDeployer();
  const result = await (deployer as any).renderManifest({
    manifestYaml: yaml.stringify({ services }),
    ...params,
    podSecurity: profile,
  });
  const docs = yaml.parseAllDocuments(result.manifestYaml).map((doc: any) => doc.toJSON());
  const pods = Object.fromEntries(
    docs.filter((doc: any) => doc.kind === 'Deployment')
      .map((doc: any) => [doc.spec.template.spec.containers[0].name, doc.spec.template.spec]),
  );
  return { result, pods, readImageConfig };
}

function ownerFindings() {
  return mocks.decide.mock.calls
    .filter((call) => call[1] === 'managed_db.owner_url')
    .map((call) => call[2]);
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.config = {};
  mocks.decide.mockImplementation(async (_db: unknown, rule: string) => (rule === 'managed_db.owner_url' ? mocks.profile : 'legacy'));
  mocks.governing.mockImplementation(async () => 'legacy');
  imageUsers = { 'web:1': '1000:1001' };
});

const web = (environment: Record<string, string>) => ({ web: { image: 'web:1', ports: ['3000'], environment } });

describe('managed_db.owner_url', () => {
  it('refuses a service that reads the owner URL under strict, naming the declared-role form', async () => {
    mocks.profile = 'strict';
    await expect(render(web({ DATABASE_URL: '${managed.db.url}' }), 'legacy'))
      .rejects.toThrow(/web.*managed\.db\.url.*managed\.db\.roles\.<role>\.url.*managed_db\.owner_url/s);
    expect(ownerFindings()).toEqual([expect.objectContaining({
      projectId: 'proj_shop',
      governing: 'project',
      actorType: 'deployer',
      actorId: 'prod/web',
      detail: expect.objectContaining({ service: 'web', references: 'managed.db.url' }),
    })]);
  });

  it('refuses the owner password too', async () => {
    mocks.profile = 'strict';
    await expect(render(web({ PGPASSWORD: '${managed.db.password}' }), 'legacy')).rejects.toThrow(/managed\.db\.password/);
  });

  it('records the service under audit and deploys it', async () => {
    mocks.profile = 'audit';
    await expect(render(web({ DATABASE_URL: '${managed.db.url}' }), 'legacy')).resolves.toBeDefined();
    expect(ownerFindings()).toHaveLength(1);
  });

  it('allows declared roles and non-secret parts under strict, and records nothing', async () => {
    mocks.profile = 'strict';
    await expect(render(web({
      DATABASE_URL: '${managed.db.roles.app.url}',
      PGHOST: '${managed.db.host}',
      PGUSER: '${managed.db.username}',
    }), 'legacy')).resolves.toBeDefined();
    expect(ownerFindings()).toEqual([]);
  });

  it('deploys a service on a schema-owner role under strict, and records nothing', async () => {
    mocks.profile = 'strict';
    imageUsers = { 'auth:1': '1000:1000' };
    const { deployer } = newDeployer();
    vi.spyOn(deployer as any, 'resolveManagedDbTenants').mockResolvedValue({
      managedValues: new Map([
        ['db.host', 'db.internal'],
        ['db.port', '5432'],
        ['db.database', 'acme-shop-prod-1a2b3c'],
        ['db.roles.gotrue.username', 'acme-shop-prod-u-1a2b3c-gotrue'],
        ['db.roles.gotrue.password', 'gotruepw'],
      ]),
      trustInputs: [],
    });
    const services = {
      db: {
        'x-eve': {
          role: 'managed_db',
          managed: {
            class: 'db.p1',
            roles: [
              { name: 'app', grants: 'readwrite' },
              { name: 'gotrue', grants: { schema: 'auth', owner: true } },
            ],
          },
        },
      },
      auth: {
        image: 'auth:1',
        ports: ['9999'],
        environment: {
          GOTRUE_DB_DATABASE_URL:
            'postgres://${managed.db.roles.gotrue.username}:${managed.db.roles.gotrue.password}@${managed.db.host}:${managed.db.port}/${managed.db.database}?search_path=auth',
        },
      },
    };
    const result = await (deployer as any).renderManifest({
      manifestYaml: yaml.stringify({ services }),
      ...params,
      podSecurity: 'legacy',
    });
    const secrets = yaml.parseAllDocuments(result.manifestYaml).map((doc: any) => doc.toJSON())
      .filter((doc: any) => doc?.kind === 'Secret');
    const values = secrets.flatMap((doc: any) => [
      ...Object.values(doc.stringData ?? {}),
      ...Object.values(doc.data ?? {}).map((v) => Buffer.from(String(v), 'base64').toString()),
    ]);
    expect(values).toContain(
      'postgres://acme-shop-prod-u-1a2b3c-gotrue:gotruepw@db.internal:5432/acme-shop-prod-1a2b3c?search_path=auth',
    );
    expect(ownerFindings()).toEqual([]);
  });
});
