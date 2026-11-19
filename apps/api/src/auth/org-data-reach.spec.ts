import { beforeEach, describe, expect, it, vi } from 'vitest';
import { HttpException } from '@nestjs/common';
import { firstValueFrom, of, toArray } from 'rxjs';
import { RbacService } from './rbac.service.js';
import { AccessService } from './access.service.js';
import { ScopedAccessService } from './scoped-access.service.js';
import { SecurityService } from '../security/security.service.js';
import { AgentMemoryController } from '../agent-memory/agent-memory.controller.js';
import { OrgDocumentsController } from '../org-documents/org-documents.controller.js';
import { OrgFsSyncController } from '../org-fs-sync/org-fs-sync.controller.js';
import type { AuthUser } from './auth.types.js';
import { accessStore as store } from './__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('./__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

/**
 * Org docs and org files reached by a route that names no single resource
 * (lists, queries, searches, object listings, event streams, shares, public
 * paths, status) are held to what the caller reaches, under the org's
 * profile (P1-6): a person through their bindings, a job token through its
 * scope. Strict filters or refuses, audit records, legacy is unchanged; org
 * owners and admins reach everything.
 */
const ORG = 'org_a';
const PROJECT = 'proj_a';
const TEAM = ['/team-a/**'];

const narrow: AuthUser = { user_id: 'user_narrow' };
const orgAdmin: AuthUser = { user_id: 'user_admin' };
const token: AuthUser = {
  user_id: 'user_narrow',
  is_job_token: true,
  job_id: 'lab-1234abcd',
  org_id: ORG,
  project_id: PROJECT,
  permissions: ['orgdocs:read', 'orgfs:read', 'orgfs:admin'],
  scope: { orgdocs: { allow_prefixes: TEAM }, orgfs: { allow_prefixes: TEAM } },
};

const inTeam = '/team-a/plan.md';
const inFinance = '/finance/budget.md';
const doc = (path: string) => ({ path, metadata: { owner: 'x' }, embedding_json: [0.1] });

function controllers() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  const scoped = new ScopedAccessService({ isEnabled: () => true } as never, access, rbac, security);
  const docs = {
    listByPrefix: vi.fn(async () => ({ documents: [doc(inTeam), doc(inFinance)] })),
    query: vi.fn(async () => ({ documents: [doc(inTeam), doc(inFinance)], pagination: { limit: 50, has_more: false, next_cursor: null } })),
    search: vi.fn(async () => ({ documents: [doc(inTeam), doc(inFinance)] })),
  };
  const memory = {
    searchMemory: vi.fn(async () => ({ data: [{ source: 'memory', path: '/team-a/memory.md' }, { source: 'memory', path: '/finance/memory.md' }] })),
    unifiedSearch: vi.fn(async () => ({ data: [{ source: 'docs', path: inTeam }, { source: 'docs', path: inFinance }] })),
  };
  const fs = {
    getStatus: vi.fn(async () => ({ org_id: ORG })),
    listObjects: vi.fn(async () => ({ data: [{ path: inTeam }, { path: inFinance }], pagination: { limit: 100, next_after: null } })),
    streamEvents: vi.fn(() => of(
      { type: 'fs_event', data: { seq: 1, path: inTeam } },
      { type: 'fs_event', data: { seq: 2, path: inFinance } },
      { type: 'fs_checkpoint', data: { cursor: 2 } },
    )),
    listShares: vi.fn(async () => ({ data: [{ id: 'shr_1', path: inTeam, url: 'u1' }, { id: 'shr_2', path: inFinance, url: 'u2' }] })),
    listPublicPaths: vi.fn(async () => ({ data: [{ id: 'pp_1', path_prefix: '/team-a/public/' }, { id: 'pp_2', path_prefix: '/finance/' }] })),
    createShare: vi.fn(async () => ({ id: 'shr_3' })),
  };
  const ctor = <T>(Type: new (...args: never[]) => T, ...args: unknown[]) => new (Type as new (...a: unknown[]) => T)(...args);
  return {
    docs, fs,
    docRoutes: ctor(OrgDocumentsController, docs, scoped),
    memoryRoutes: ctor(AgentMemoryController, memory, scoped, rbac),
    fsRoutes: ctor(OrgFsSyncController, fs, scoped),
  };
}

function seed(orgProfile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme', orgProfile);
  store.addProject(PROJECT, ORG, 'lab');
  store.joinOrg(narrow.user_id, ORG, 'member');
  store.bind({
    org_id: ORG, principal_id: narrow.user_id, permissions: ['orgdocs:read', 'orgfs:read', 'orgfs:admin'],
    scope_json: { orgdocs: { allow_prefixes: TEAM }, orgfs: { allow_prefixes: TEAM } },
  });
  store.joinOrg(orgAdmin.user_id, ORG, 'admin');
  store.bind({ org_id: ORG, principal_id: orgAdmin.user_id, permissions: ['orgdocs:read', 'orgfs:read', 'orgfs:admin'], scope_json: { orgdocs: { allow_prefixes: ['/**'] }, orgfs: { allow_prefixes: ['/**'] } } });
  store.addJudgedJob(token.job_id!);
}

const paths = (rows: Array<Record<string, unknown>>) => rows.map((row) => row.path ?? row.path_prefix);

/** Every route under test, as the caller sees it. */
async function view(caller: AuthUser) {
  const c = controllers();
  const settle = <T>(promise: Promise<T>) => promise.then((value) => value, (error) => error as Error);
  return {
    list: await settle(c.docRoutes.list(ORG, caller, undefined, undefined, 100)),
    query: await settle(c.docRoutes.query(ORG, {} as never, caller, undefined)),
    search: await settle(c.docRoutes.search(ORG, 'plan', 20, undefined, undefined, caller, undefined)),
    memory: await settle(c.memoryRoutes.searchMemory(ORG, 'plan', undefined, 20, caller, undefined)),
    unified: await settle(c.memoryRoutes.unifiedSearch(ORG, 'plan', undefined, 20, undefined, caller, undefined)),
    objects: await settle(c.fsRoutes.listObjects(ORG, undefined, 100, undefined, caller, undefined)),
    financeObjects: await settle(c.fsRoutes.listObjects(ORG, '/finance/', 100, undefined, caller, undefined)),
    stream: await settle(c.fsRoutes.streamEvents(ORG, 0, caller, undefined).then((events) => firstValueFrom(events.pipe(toArray())))),
    status: await settle(c.fsRoutes.status(ORG, caller, undefined)),
    shares: await settle(c.fsRoutes.listShares(ORG, caller, undefined)),
    publicPaths: await settle(c.fsRoutes.listPublicPaths(ORG, caller, undefined)),
    financeShare: await settle(c.fsRoutes.createShare(ORG, { path: inFinance } as never, caller, undefined)),
  };
}

type View = Awaited<ReturnType<typeof view>>;

function expectHeldToTeam(v: View) {
  expect(paths((v.list as unknown as { documents: never[] }).documents)).toEqual([inTeam]);
  expect(paths((v.query as unknown as { documents: never[] }).documents)).toEqual([inTeam]);
  expect(paths((v.search as unknown as { documents: never[] }).documents)).toEqual([inTeam]);
  expect(paths((v.memory as unknown as { data: never[] }).data)).toEqual(['/team-a/memory.md']);
  expect(paths((v.unified as unknown as { data: never[] }).data)).toEqual([inTeam]);
  expect(paths((v.objects as unknown as { data: never[] }).data)).toEqual([inTeam]);
  expect(v.financeObjects).toBeInstanceOf(HttpException);
  expect((v.stream as Array<{ data: { path?: string } }>).map((event) => event.data.path ?? 'checkpoint')).toEqual([inTeam, 'checkpoint']);
  expect(v.status).toBeInstanceOf(HttpException);
  expect(paths((v.shares as unknown as { data: never[] }).data)).toEqual([inTeam]);
  expect(paths((v.publicPaths as unknown as { data: never[] }).data)).toEqual(['/team-a/public/']);
  expect(v.financeShare).toBeInstanceOf(HttpException);
}

function expectEverything(v: View) {
  expect((v.list as unknown as { documents: never[] }).documents).toHaveLength(2);
  expect((v.query as unknown as { documents: never[] }).documents).toHaveLength(2);
  expect((v.search as unknown as { documents: never[] }).documents).toHaveLength(2);
  expect((v.memory as unknown as { data: never[] }).data).toHaveLength(2);
  expect((v.unified as unknown as { data: never[] }).data).toHaveLength(2);
  expect((v.objects as unknown as { data: never[] }).data).toHaveLength(2);
  expect(v.financeObjects).not.toBeInstanceOf(Error);
  expect(v.stream).toHaveLength(3);
  expect(v.status).not.toBeInstanceOf(Error);
  expect((v.shares as unknown as { data: never[] }).data).toHaveLength(2);
  expect((v.publicPaths as unknown as { data: never[] }).data).toHaveLength(2);
  expect(v.financeShare).not.toBeInstanceOf(Error);
}

describe('org docs and files reached by routes that name no resource (P1-6)', () => {
  beforeEach(() => vi.clearAllMocks());

  describe('under a strict org', () => {
    beforeEach(() => seed('strict'));

    it('hold a person with a narrow binding to it', async () => {
      expectHeldToTeam(await view(narrow));
    });

    it('hold a scoped job token to its scope', async () => {
      expectHeldToTeam(await view(token));
    });

    it('leave org admins everything', async () => {
      expectEverything(await view(orgAdmin));
    });
  });

  describe('under an audit org', () => {
    beforeEach(() => seed('audit'));

    it('serve everything and record what strict would hold back', async () => {
      expectEverything(await view(narrow));
      expect(store.findings('access.org_data_route_scope')[0]).toMatchObject({ profile: 'audit', actor_id: narrow.user_id });
    });
  });

  describe('under a legacy org', () => {
    beforeEach(() => seed('legacy'));

    it('change nothing and record nothing', async () => {
      expectEverything(await view(narrow));
      expect(store.findings()).toEqual([]);
    });
  });
});
