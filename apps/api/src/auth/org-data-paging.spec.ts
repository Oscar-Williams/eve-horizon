import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RbacService } from './rbac.service.js';
import { AccessService } from './access.service.js';
import { ScopedAccessService } from './scoped-access.service.js';
import { SecurityService } from '../security/security.service.js';
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
 * Paged listings of org files and docs (P1-6): under a strict org a page
 * holds only what the caller reaches, and its cursor is taken from the last
 * item the caller sees, so following cursors never reveals another path.
 */
const ORG = 'org_a';
const TEAM = ['/team-a/**'];
const narrow: AuthUser = { user_id: 'user_narrow' };
const token: AuthUser = {
  user_id: 'user_narrow', is_job_token: true, job_id: 'lab-1234abcd', org_id: ORG, project_id: 'proj_a',
  permissions: ['orgdocs:read', 'orgfs:read'],
  scope: { orgdocs: { allow_prefixes: TEAM }, orgfs: { allow_prefixes: TEAM } },
};

const PATHS = ['/finance/a.xlsx', '/finance/b.xlsx', '/team-a/1.md', '/team-a/2.md', '/zeta/x.md'];

/** Object listing as the service pages it: by path, after a cursor, with the last path as the next cursor. */
function listObjects(_org: string, opts: { limit?: number; after?: string } = {}) {
  const limit = Math.max(1, Math.min(opts.limit ?? 100, 500));
  const rows = PATHS.filter((path) => !opts.after || path > opts.after).slice(0, limit).map((path) => ({ path }));
  return Promise.resolve({ data: rows, pagination: { limit, next_after: rows.length > 0 ? rows[rows.length - 1].path : null } });
}

/** Doc query as the service pages it: newest first, with an opaque cursor of the last doc. */
const DOCS = PATHS.map((path, i) => ({ id: `doc_${i}`, path, updated_at: new Date(Date.UTC(2026, 10, 19, 12, 0, 50 - i)).toISOString() }));
const encode = (doc: { id: string; updated_at: string }) => Buffer.from(JSON.stringify({ updated_at: doc.updated_at, id: doc.id })).toString('base64');
const decode = (cursor: string) => JSON.parse(Buffer.from(cursor, 'base64').toString()) as { id: string };
function queryDocs(_org: string, body: { limit?: number; cursor?: string | null }) {
  const limit = body.limit ?? 50;
  const start = body.cursor ? DOCS.findIndex((doc) => doc.id === decode(body.cursor!).id) + 1 : 0;
  const rows = DOCS.slice(start, start + limit + 1);
  const hasMore = rows.length > limit;
  const page = rows.slice(0, limit);
  return Promise.resolve({
    documents: page,
    pagination: { limit, has_more: hasMore, next_cursor: hasMore ? encode(page[page.length - 1]) : null },
  });
}

function controllers() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  const scoped = new ScopedAccessService({ isEnabled: () => true } as never, access, rbac, security);
  const docs = { query: vi.fn(queryDocs), cursorFor: encode };
  const fs = { listObjects: vi.fn(listObjects) };
  const ctor = <T>(Type: new (...args: never[]) => T, ...args: unknown[]) => new (Type as new (...a: unknown[]) => T)(...args);
  return { docRoutes: ctor(OrgDocumentsController, docs, scoped), fsRoutes: ctor(OrgFsSyncController, fs, scoped) };
}

function seed(orgProfile: 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme', orgProfile);
  store.addProject('proj_a', ORG, 'deals');
  store.joinOrg(narrow.user_id, ORG, 'member');
  store.bind({
    org_id: ORG, principal_id: narrow.user_id, permissions: ['orgdocs:read', 'orgfs:read'],
    scope_json: { orgdocs: { allow_prefixes: TEAM }, orgfs: { allow_prefixes: TEAM } },
  });
  store.addJudgedJob(token.job_id!);
}

/** Follows the object cursors page by page; returns what was listed and every cursor seen. */
async function walkObjects(caller: AuthUser) {
  const c = controllers();
  const listed: string[] = [];
  const cursors: Array<string | null> = [];
  let after: string | undefined;
  for (let i = 0; i < 10; i++) {
    const page = await c.fsRoutes.listObjects(ORG, undefined, 1, after, caller, undefined);
    listed.push(...page.data.map((object) => object.path));
    cursors.push(page.pagination.next_after);
    if (!page.pagination.next_after) break;
    after = page.pagination.next_after;
  }
  return { listed, cursors };
}

async function walkDocs(caller: AuthUser) {
  const c = controllers();
  const listed: string[] = [];
  const cursors: string[] = [];
  let cursor: string | null = null;
  for (let i = 0; i < 10; i++) {
    const page = await c.docRoutes.query(ORG, { limit: 1, cursor } as never, caller, undefined);
    listed.push(...page.documents.map((doc) => doc.path));
    if (!page.pagination.next_cursor) break;
    cursors.push(page.pagination.next_cursor);
    cursor = page.pagination.next_cursor;
  }
  return { listed, cursorDocs: cursors.map((value) => DOCS.find((doc) => doc.id === decode(value).id)?.path) };
}

describe('paged org file and doc listings (P1-6)', () => {
  beforeEach(() => vi.clearAllMocks());

  describe('under a strict org', () => {
    beforeEach(() => seed('strict'));

    it.each([['a person with a narrow binding', narrow], ['a scoped job token', token]])(
      'give %s cursors only from paths they reach',
      async (_label, caller) => {
        const objects = await walkObjects(caller as AuthUser);
        expect(objects.listed).toEqual(['/team-a/1.md', '/team-a/2.md']);
        expect(objects.cursors.filter((cursor) => cursor !== null).every((cursor) => cursor!.startsWith('/team-a/'))).toBe(true);

        const docs = await walkDocs(caller as AuthUser);
        expect(docs.listed).toEqual(['/team-a/1.md', '/team-a/2.md']);
        expect(docs.cursorDocs.every((path) => path?.startsWith('/team-a/'))).toBe(true);
        expect(store.findings('access.org_data_route_scope')[0]).toMatchObject({ profile: 'strict' });
      },
    );
  });

  describe('under an audit org', () => {
    beforeEach(() => seed('audit'));

    it('pages as before and records what strict would hold back', async () => {
      const c = controllers();

      await expect(c.fsRoutes.listObjects(ORG, undefined, 1, undefined, narrow, undefined))
        .resolves.toEqual({ data: [{ path: '/finance/a.xlsx' }], pagination: { limit: 1, next_after: '/finance/a.xlsx' } });
      const docs = await c.docRoutes.query(ORG, { limit: 1 } as never, narrow, undefined);
      expect(docs.documents.map((doc) => doc.path)).toEqual(['/finance/a.xlsx']);
      expect(store.findings('access.org_data_route_scope')[0]).toMatchObject({ profile: 'audit' });
    });
  });
});
