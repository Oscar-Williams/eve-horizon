import { beforeEach, afterEach, describe, expect, it, vi } from 'vitest';
import { EnvDbService } from './env-db.service';
import type { SecretsService } from '../secrets/secrets.service';

// `eve db reset` (and `wipe`, which is reset without migrations) drops and
// recreates the `public` schema. Extensions installed there and the declared
// roles' grants go with it, so reset puts them back in the same transaction.

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

describe('EnvDbService reset keeps extensions and role grants', () => {
  let service: EnvDbService;
  const context = { user_id: 'user_1', project_id: 'proj_1', env_name: 'dev' };

  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubEnv('DATABASE_URL', PLATFORM_DATABASE_URL);
    mocks.statements = [];
    mocks.publicExtensions = ['pg_trgm'];
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
    mocks.managedDb.listTenantRoles.mockResolvedValue([
      { id: 'mdbr_app', tenant_id: 'mdbt_1', name: 'app', grants: 'readwrite', db_user: `${OWNER}-app` },
      { id: 'mdbr_reports', tenant_id: 'mdbt_1', name: 'reports', grants: 'readonly', db_user: `${OWNER}-reports` },
    ]);
    mocks.accessGroups.listGroupIdsForPrincipal.mockResolvedValue([]);
    mocks.createDb.mockImplementation(() => fakeClient());
    mocks.lookup.mockImplementation(async () => [{ address: '203.0.113.40', family: 4 }]);
    const secrets = { resolveProjectSecretValue: vi.fn(async () => null) };
    service = new EnvDbService({} as never, secrets as unknown as SecretsService);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('reinstalls the extensions that lived in public, after the drop', async () => {
    await expect(service.reset('proj_1', 'dev', { force: true, no_migrate: true }, context))
      .resolves.toMatchObject({ reset: true });

    const drop = mocks.statements.findIndex((s) => s.startsWith('DROP SCHEMA IF EXISTS public CASCADE'));
    const ext = mocks.statements.indexOf('CREATE EXTENSION IF NOT EXISTS "pg_trgm" SCHEMA "public"');
    expect(drop).toBeGreaterThanOrEqual(0);
    expect(ext).toBeGreaterThan(drop);
  });

  it('grants the declared roles their schema and default privileges again', async () => {
    await service.reset('proj_1', 'dev', { force: true, no_migrate: true }, context);

    expect(mocks.statements).toEqual(expect.arrayContaining([
      `GRANT USAGE ON SCHEMA "public" TO "${OWNER}-app"`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE "${OWNER}" IN SCHEMA "public" GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO "${OWNER}-app"`,
      `GRANT USAGE ON SCHEMA "public" TO "${OWNER}-reports"`,
      `ALTER DEFAULT PRIVILEGES FOR ROLE "${OWNER}" IN SCHEMA "public" GRANT SELECT ON SEQUENCES TO "${OWNER}-reports"`,
    ]));
  });

  it('restores nothing for a database that is not managed', async () => {
    mocks.manifests.findLatestByProject.mockResolvedValue(null);
    mocks.environments.findByProjectAndName.mockResolvedValue({
      id: 'env_1', name: 'dev', namespace: null, db_ref: null,
      overrides_json: { db: { url: 'postgres://app:pw@db.tenant.example:5432/app' } },
    });

    await service.reset('proj_1', 'dev', { force: true, no_migrate: true }, context);

    expect(mocks.managedDb.listTenantRoles).not.toHaveBeenCalled();
    expect(mocks.statements.some((s) => s.startsWith('GRANT'))).toBe(false);
    expect(mocks.statements).toContain('CREATE EXTENSION IF NOT EXISTS "pg_trgm" SCHEMA "public"');
  });
});
