import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException } from '@nestjs/common';
import { RbacService } from './rbac.service.js';
import { AccessService } from './access.service.js';
import { ScopedAccessService } from './scoped-access.service.js';
import { SecurityService } from '../security/security.service.js';
import { AgentMemoryController } from '../agent-memory/agent-memory.controller.js';
import { OrgDocumentsController } from '../org-documents/org-documents.controller.js';
import { OrgFsSyncController } from '../org-fs-sync/org-fs-sync.controller.js';
import { CloudFsController } from '../cloud-fs/cloud-fs.controller.js';
import type { AuthUser } from './auth.types.js';
import { accessStore as store } from './__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('./__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

/**
 * Org-data routes that name no single resource (search, listings, KV,
 * distillation, device enrolment, default mounts) hold a job token to its
 * declared scope under the org's profile (P1-6): strict filters the results
 * to the scope or refuses, audit records what strict would hold back.
 */
const ORG = 'org_a';
const PROJECT = 'proj_a';
const OTHER = 'proj_b';

const token: AuthUser = {
  user_id: 'user_pa',
  is_job_token: true,
  job_id: 'lab-1234abcd',
  org_id: ORG,
  project_id: PROJECT,
  permissions: ['orgdocs:read', 'orgdocs:write', 'orgfs:write', 'cloud_fs:read', 'jobs:read', 'events:read'],
  scope: { orgdocs: { allow_prefixes: ['/team-a/**'] }, orgfs: { allow_prefixes: ['/team-a/**'] } },
};

const docs = [
  { path: '/team-a/plan.md' },
  { path: '/finance/budget.md' },
];

function controllers() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  const scoped = new ScopedAccessService({ isEnabled: () => true } as never, access, rbac, security);
  const memory = {
    memoryPath: (agent: string, category: string, key: string) => `/agents/${agent}/memory/${category}/${key}.md`,
    kvPath: (agent: string, namespace: string, key?: string) => `/agents/${agent}/kv/${namespace}${key ? `/${key}` : ''}`,
    distillTargetPath: (threadId: string, input: { to_path?: string }) => input.to_path ?? `/agents/shared/memory/decisions/thread-${threadId}.md`,
    searchMemory: vi.fn(async () => ({ data: [{ source: 'memory', path: '/agents/scout/memory/learnings/a.md' }] })),
    kvGet: vi.fn(async () => ({ key: 'k' })),
    distillThread: vi.fn(async () => ({ status: 'written' })),
    unifiedSearch: vi.fn(async () => ({
      data: [
        { source: 'docs', path: '/team-a/plan.md' },
        { source: 'docs', path: '/finance/budget.md' },
        { source: 'threads', thread_id: 'thr_org', message_id: 'msg_1' },
        { source: 'attachments', job_id: 'lab-1234abcd', project_id: PROJECT, name: 'mine.md' },
        { source: 'attachments', job_id: 'other-1', project_id: OTHER, name: 'theirs.md' },
      ],
    })),
  };
  const orgDocs = {
    search: vi.fn(async () => ({ documents: docs })),
    listStale: vi.fn(async () => ({ documents: docs })),
  };
  const orgFs = { enrollDevice: vi.fn(async () => ({ device_id: 'dev_1' })) };
  const cloudFs = {
    listMounts: vi.fn(async () => [{ id: 'cfm_1', org_id: ORG, project_id: null }]),
    browse: vi.fn(async () => ({ mount_id: 'cfm_1', path: '/', entries: [] })),
  };
  const ctor = <T>(Type: new (...args: never[]) => T, ...args: unknown[]) => new (Type as new (...a: unknown[]) => T)(...args);
  return {
    memory,
    orgFs,
    memoryRoutes: ctor(AgentMemoryController, memory, scoped, rbac),
    docRoutes: ctor(OrgDocumentsController, orgDocs, scoped),
    fsRoutes: ctor(OrgFsSyncController, orgFs, scoped),
    cloudRoutes: ctor(CloudFsController, cloudFs, scoped),
  };
}

function seed(orgProfile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme', orgProfile);
  store.addProject(PROJECT, ORG, 'lab');
  store.addProject(OTHER, ORG, 'other');
}

const paths = (rows: Array<Record<string, unknown>>) => rows.map((row) => row.path ?? row.name ?? row.thread_id);

describe('org-data routes that name no resource, for job tokens (P1-6)', () => {
  beforeEach(() => vi.clearAllMocks());

  describe('under a strict org', () => {
    beforeEach(() => seed('strict'));

    it('filter searches and listings to the token\'s scope', async () => {
      const c = controllers();

      const found = await c.docRoutes.search(ORG, 'plan', 20, undefined, undefined, token, undefined);
      expect(paths(found.documents as never)).toEqual(['/team-a/plan.md']);
      const stale = await c.docRoutes.stale(ORG, undefined, undefined, 100, token, undefined);
      expect(paths(stale.documents as never)).toEqual(['/team-a/plan.md']);
      const memories = await c.memoryRoutes.searchMemory(ORG, 'a', undefined, 20, token, undefined) as { data: never[] };
      expect(memories.data).toEqual([]);
    });

    it('limit org search to the token\'s project and the org docs its scope allows', async () => {
      const c = controllers();

      const result = await c.memoryRoutes.unifiedSearch(ORG, 'plan', undefined, 20, undefined, token, undefined) as { data: never[] };
      expect(paths(result.data)).toEqual(['/team-a/plan.md', 'mine.md']);
    });

    it('refuse KV, distillation and device enrolment outside the scope', async () => {
      const c = controllers();

      await expect(c.memoryRoutes.kvGet(ORG, 'scout', 'notes', 'k', token, undefined)).rejects.toBeInstanceOf(HttpException);
      await expect(c.memoryRoutes.distillThread(ORG, 'thr_org', { to_path: '/finance/digest.md' }, token, undefined))
        .rejects.toBeInstanceOf(HttpException);
      await expect(c.memoryRoutes.distillThread(ORG, 'thr_org', { to_path: '/team-a/digest.md' }, token, undefined))
        .resolves.toBeDefined();
      await expect(c.fsRoutes.enrollDevice(ORG, { name: 'laptop' } as never, token, undefined)).rejects.toBeInstanceOf(HttpException);
      expect(c.orgFs.enrollDevice).not.toHaveBeenCalled();
    });

    it('give cloud-fs listing and default-mount reads only through a cloud_fs scope entry', async () => {
      const c = controllers();

      await expect(c.cloudRoutes.listMounts(ORG, token)).resolves.toEqual({ mounts: [] });
      await expect(c.cloudRoutes.browse(ORG, token, {})).rejects.toBeInstanceOf(HttpException);
      const mounted = { ...token, scope: { cloud_fs: { allow_mount_ids: ['cfm_1'] } } };
      await expect(c.cloudRoutes.listMounts(ORG, mounted)).resolves.toMatchObject({ mounts: [{ id: 'cfm_1' }] });
    });
  });

  describe('under an audit org', () => {
    beforeEach(() => seed('audit'));

    it('serve everything and record what strict would hold back', async () => {
      const c = controllers();

      const found = await c.docRoutes.search(ORG, 'plan', 20, undefined, undefined, token, undefined);
      expect(found.documents).toHaveLength(2);
      await expect(c.memoryRoutes.kvGet(ORG, 'scout', 'notes', 'k', token, undefined)).resolves.toBeDefined();
      await expect(c.fsRoutes.enrollDevice(ORG, { name: 'laptop' } as never, token, undefined)).resolves.toBeDefined();
      await expect(c.cloudRoutes.listMounts(ORG, token)).resolves.toMatchObject({ mounts: [{ id: 'cfm_1' }] });
      expect(store.findings('access.org_data_route_scope')[0]).toMatchObject({ profile: 'audit', actor_type: 'job' });
    });
  });

  describe('under a legacy org', () => {
    beforeEach(() => seed('legacy'));

    it('change nothing and record nothing', async () => {
      const c = controllers();

      const found = await c.docRoutes.search(ORG, 'plan', 20, undefined, undefined, token, undefined);
      expect(found.documents).toHaveLength(2);
      const result = await c.memoryRoutes.unifiedSearch(ORG, 'plan', undefined, 20, undefined, token, undefined) as { data: never[] };
      expect(result.data).toHaveLength(5);
      await expect(c.memoryRoutes.kvGet(ORG, 'scout', 'notes', 'k', token, undefined)).resolves.toBeDefined();
      await expect(c.cloudRoutes.browse(ORG, token, {})).resolves.toBeDefined();
      expect(store.findings()).toEqual([]);
    });
  });
});
