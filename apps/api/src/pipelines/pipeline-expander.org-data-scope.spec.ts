import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException } from '@nestjs/common';
import { PipelineExpanderService } from './pipeline-expander.service.js';
import { RbacService } from '../auth/rbac.service.js';
import { AccessService } from '../auth/access.service.js';
import { SecurityService } from '../security/security.service.js';
import { accessStore as store } from '../auth/__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('../auth/__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

/**
 * Pipeline steps' declared scopes are judged as workflow steps' are (P1-6):
 * against the user who started the run, and refused for runs no user
 * started when they reach org data, under the org's profile.
 */
const ORG = 'org_a';
const PROJECT = 'proj_a';
const PROJECT_ADMIN = 'user_pa';
const ORG_ADMIN = 'user_oa';

const MANIFEST = `
name: test
pipelines:
  sync:
    steps:
      - name: pull
        scope:
          cloud_fs:
            allow_mount_ids: ['*']
        action:
          type: run
          command: "true"
`;

let created: Array<Record<string, unknown>> = [];

function service(): PipelineExpanderService {
  created = [];
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  const svc = new (PipelineExpanderService as unknown as new (...args: unknown[]) => PipelineExpanderService)({}, access, security);
  let n = 0;
  const internals = svc as unknown as Record<string, unknown>;
  internals.projects = { findById: vi.fn(async () => ({ id: PROJECT, org_id: ORG, slug: 'lab' })) };
  internals.manifests = {
    findByProjectAndGitSha: vi.fn(async () => null),
    findLatestByProject: vi.fn(async () => ({ manifest_yaml: MANIFEST, manifest_hash: 'hash_1' })),
  };
  internals.runs = {
    createRun: vi.fn(async (data: Record<string, unknown>) => ({
      ...data, started_at: null, completed_at: null,
      created_at: new Date('2026-11-19T00:00:00Z'), updated_at: new Date('2026-11-19T00:00:00Z'),
    })),
    findActiveRunByDedupeKey: vi.fn(async () => null),
    listStepRuns: vi.fn(async () => []),
    updateRun: vi.fn(),
    updateStepRun: vi.fn(),
  };
  internals.jobs = {
    generateJobId: vi.fn(async () => ({ id: `job_${++n}` })),
    create: vi.fn(async (data: Record<string, unknown>) => {
      created.push(data);
      return { ...data, created_at: new Date('2026-11-19T00:00:00Z'), updated_at: new Date('2026-11-19T00:00:00Z') };
    }),
    addDependency: vi.fn(async () => undefined),
  };
  return svc;
}

function seed(orgProfile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme', orgProfile);
  store.addProject(PROJECT, ORG, 'lab');
  store.joinOrg(PROJECT_ADMIN, ORG, 'member');
  store.joinProject(PROJECT_ADMIN, PROJECT, 'admin');
  store.joinOrg(ORG_ADMIN, ORG, 'admin');
}

const run = { pipeline_name: 'sync', git_sha: 'abc123' };

describe('pipeline step scopes (P1-6)', () => {
  beforeEach(() => vi.clearAllMocks());

  describe('under a strict org', () => {
    beforeEach(() => seed('strict'));

    it('refuse a scope outside the starter\'s bindings', async () => {
      await expect(service().expandPipeline(PROJECT, run as never, PROJECT_ADMIN)).rejects.toBeInstanceOf(BadRequestException);
      expect(created).toEqual([]);
      expect(store.findings('access.org_data_scope_wide')[0]).toMatchObject({ profile: 'strict', org_id: ORG });
    });

    it('refuse org data in the scope of a run no user started', async () => {
      await expect(service().expandPipeline(PROJECT, run as never, undefined)).rejects.toBeInstanceOf(BadRequestException);
      expect(created).toEqual([]);
    });

    it('mark the scope judged when the starter may hold it', async () => {
      await service().expandPipeline(PROJECT, run as never, ORG_ADMIN);
      expect(created[0]).toMatchObject({ token_scope: { cloud_fs: { allow_mount_ids: ['*'] } } });
      expect(created[0].token_scope_judged_at).toBeInstanceOf(Date);
    });
  });

  describe('under an audit org', () => {
    beforeEach(() => seed('audit'));

    it('create the jobs, record the scope and leave it unjudged', async () => {
      const svc = service();
      await svc.expandPipeline(PROJECT, run as never, PROJECT_ADMIN);
      await svc.expandPipeline(PROJECT, run as never, undefined);

      expect(created).toHaveLength(2);
      expect(created.map((job) => job.token_scope_judged_at ?? null)).toEqual([null, null]);
      expect(store.findings('access.org_data_scope_wide')[0]).toMatchObject({ profile: 'audit' });
      expect(store.findings('access.org_data_no_user')[0]).toMatchObject({ profile: 'audit' });
    });
  });

  describe('under a legacy org', () => {
    beforeEach(() => seed('legacy'));

    it('create the jobs and record nothing', async () => {
      const svc = service();
      await svc.expandPipeline(PROJECT, run as never, PROJECT_ADMIN);
      await svc.expandPipeline(PROJECT, run as never, undefined);

      expect(created).toHaveLength(2);
      expect(store.findings()).toEqual([]);
    });
  });
});
