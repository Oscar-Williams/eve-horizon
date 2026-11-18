import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException } from '@nestjs/common';
import { CloudFsController } from './cloud-fs.controller.js';
import { RbacService } from '../auth/rbac.service.js';
import { AccessService } from '../auth/access.service.js';
import { ScopedAccessService } from '../auth/scoped-access.service.js';
import { SecurityService } from '../security/security.service.js';
import type { AuthUser } from '../auth/auth.types.js';
import { accessStore as store } from '../../test/unit/helpers/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('../../test/unit/helpers/access-store.js');
  return { ...actual, ...accessStore.queries };
});

const ORG = 'org_a';

/** A job token with no scope, for a run a user started. */
const unscoped: AuthUser = {
  user_id: 'user_pa', is_job_token: true, job_id: 'lab-1', org_id: ORG, project_id: 'proj_a', permissions: ['cloud_fs:read'],
};

function controller() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const scoped = new ScopedAccessService({ isEnabled: () => true } as never, new AccessService(rbac, store.db as never, security), rbac, security);
  const cloudFs = {
    listMounts: vi.fn(async () => [{ id: 'cfm_1', org_id: ORG }]),
    browse: vi.fn(async () => ({ mount_id: 'cfm_1', path: '/', entries: [] })),
    search: vi.fn(async () => ({ mount_id: 'cfm_1', entries: [] })),
  };
  return { controller: new CloudFsController(cloudFs as never, scoped), cloudFs };
}

function seed(orgProfile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme', orgProfile);
  store.addProject('proj_a', ORG, 'lab');
}

describe('cloud-fs routes that name no mount, for job tokens (P1-6)', () => {
  it('refuse an unscoped job token under a strict org', async () => {
    seed('strict');
    const { controller: c, cloudFs } = controller();

    await expect(c.listMounts(ORG, unscoped)).rejects.toBeInstanceOf(HttpException);
    await expect(c.browse(ORG, unscoped, {})).rejects.toBeInstanceOf(HttpException);
    await expect(c.search(ORG, unscoped, { q: 'deal' })).rejects.toBeInstanceOf(HttpException);
    expect(cloudFs.browse).not.toHaveBeenCalled();
    expect(cloudFs.search).not.toHaveBeenCalled();
  });

  it('serve it under an audit org and record the access', async () => {
    seed('audit');
    const { controller: c } = controller();

    await expect(c.listMounts(ORG, unscoped)).resolves.toMatchObject({ mounts: [{ id: 'cfm_1' }] });
    await expect(c.browse(ORG, unscoped, {})).resolves.toMatchObject({ mount_id: 'cfm_1' });
    expect(store.findings('access.org_data_unscoped')[0]).toMatchObject({ profile: 'audit', org_id: ORG });
  });

  beforeEach(() => vi.clearAllMocks());
});
