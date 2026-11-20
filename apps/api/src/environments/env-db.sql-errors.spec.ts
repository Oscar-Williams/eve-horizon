import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException } from '@nestjs/common';
import { EnvDbService } from './env-db.service';
import type { SecretsService } from '../secrets/secrets.service';

// `eve db sql` reports the tenant's own SQL mistakes (a missing table, a bad
// column) as 400 with Postgres's code and message, so they cannot be taken
// for a platform fault. Connection and server failures stay errors.

const PLATFORM_DATABASE_URL = 'postgres://eve:platform-pass@eve-db.internal:5432/eve';
const OWNER = 'acme-shop-dev-u-1a2b3c';
const MANAGED_URL = `postgres://${OWNER}:tenant-pass@db.tenant.example:5432/acme-shop-dev-1a2b3c`;

const mocks = vi.hoisted(() => ({
  createDb: vi.fn(),
  lookup: vi.fn(),
  projects: { findById: vi.fn() },
  environments: { findByProjectAndName: vi.fn() },
  manifests: { findLatestByProject: vi.fn() },
  orgs: { findById: vi.fn() },
  managedDb: { findReadyTenantByEnv: vi.fn(), listTenantsByOrg: vi.fn(), listTenantRoles: vi.fn() },
  accessGroups: { listGroupIdsForPrincipal: vi.fn() },
  publicExtensions: [] as string[],
  statements: [] as string[],
  failWith: null as null | { code: string; message: string },
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  createDbFromTarget: mocks.createDb,
  projectQueries: vi.fn(() => mocks.projects),
  environmentQueries: vi.fn(() => mocks.environments),
  projectManifestQueries: vi.fn(() => mocks.manifests),
  orgQueries: vi.fn(() => mocks.orgs),
  managedDbQueries: vi.fn(() => mocks.managedDb),
  accessGroupQueries: vi.fn(() => mocks.accessGroups),
}));

vi.mock('node:dns/promises', () => ({
  lookup: mocks.lookup,
  default: { lookup: mocks.lookup },
}));

function fakeClient() {
  const tx = Object.assign(
    vi.fn(async (strings: TemplateStringsArray) => {
      const text = strings.join('?').replace(/\s+/g, ' ').trim();
      mocks.statements.push(text);
      if (text.includes('pg_extension')) return mocks.publicExtensions.map((extname) => ({ extname }));
      return [];
    }),
    {
      unsafe: vi.fn(async (text: string) => {
        mocks.statements.push(text.replace(/\s+/g, ' ').trim());
        if (mocks.failWith && !text.startsWith('SET ')) {
          throw Object.assign(new Error(mocks.failWith.message), { name: 'PostgresError', code: mocks.failWith.code, severity: 'ERROR' });
        }
        return [];
      }),
    },
  );
  return Object.assign(vi.fn(async () => [{ privileged: false }]), {
    tx,
    unsafe: vi.fn(async () => []),
    begin: vi.fn(async (callback: (t: typeof tx) => unknown) => callback(tx)),
    end: vi.fn(async () => {}),
  });
}

const MANAGED_MANIFEST = [
  'services:',
  '  db:',
  '    x-eve:',
  '      role: managed_db',
  '      managed:',
  '        class: db.p1',
  '        engine: postgres',
].join('\n');

describe('EnvDbService SQL errors', () => {
  let service: EnvDbService;
  const context = { user_id: 'user_1', project_id: 'proj_1', env_name: 'dev' };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv('DATABASE_URL', PLATFORM_DATABASE_URL);
    mocks.statements = [];
    mocks.failWith = null;
    mocks.projects.findById.mockResolvedValue({ id: 'proj_1', org_id: 'org_1', slug: 'shop' });
    mocks.environments.findByProjectAndName.mockResolvedValue({
      id: 'env_1', name: 'dev', namespace: null, db_ref: null, overrides_json: {},
    });
    mocks.manifests.findLatestByProject.mockResolvedValue({ manifest_yaml: MANAGED_MANIFEST });
    mocks.orgs.findById.mockResolvedValue({ id: 'org_1', slug: 'acme' });
    mocks.managedDb.findReadyTenantByEnv.mockResolvedValue({
      id: 'mdbt_1', status: 'ready', db_user: OWNER, credential_secret_ref: MANAGED_URL,
    });
    mocks.managedDb.listTenantsByOrg.mockResolvedValue([]);
    mocks.managedDb.listTenantRoles.mockResolvedValue([]);
    mocks.accessGroups.listGroupIdsForPrincipal.mockResolvedValue([]);
    mocks.createDb.mockImplementation(() => fakeClient());
    mocks.lookup.mockImplementation(async () => [{ address: '203.0.113.40', family: 4 }]);
    const secrets = { resolveProjectSecretValue: vi.fn(async () => null) };
    service = new EnvDbService({} as never, secrets as unknown as SecretsService);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  const run = (write: boolean) => service.executeSql('proj_1', 'dev', 'SELECT 1 FROM no_such_table', undefined, write, context);

  for (const write of [false, true]) {
    it(`answers a query error with 400, its code and message (${write ? 'write' : 'read-only'})`, async () => {
      mocks.failWith = { code: '42P01', message: 'relation "no_such_table" does not exist' };
      const error = await run(write).catch((e: unknown) => e);
      expect(error).toBeInstanceOf(BadRequestException);
      expect((error as BadRequestException).message).toContain('42P01');
      expect((error as BadRequestException).message).toContain('relation "no_such_table" does not exist');
    });
  }

  it('leaves connection and server failures as errors', async () => {
    for (const code of ['08006', '57P01', '53300', 'XX000']) {
      mocks.failWith = { code, message: 'server trouble' };
      const error = await run(false).catch((e: unknown) => e);
      expect(error).not.toBeInstanceOf(BadRequestException);
    }
  });
});
