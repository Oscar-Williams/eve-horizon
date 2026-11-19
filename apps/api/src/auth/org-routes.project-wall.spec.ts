import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { RbacService } from './rbac.service.js';
import { AccessService } from './access.service.js';
import { ScopedAccessService } from './scoped-access.service.js';
import { SecurityService } from '../security/security.service.js';
import { OrgThreadsController } from '../threads/org-threads.controller.js';
import { ResourcesController } from '../resources/resources.controller.js';
import { AgentMemoryController } from '../agent-memory/agent-memory.controller.js';
import type { AuthUser } from './auth.types.js';
import { accessStore as store } from './__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('./__tests__/access-store.js');
  return { ...actual, ...accessStore.queries };
});

/**
 * Org-addressed routes that reach a project's threads, job attachments and
 * events by id or by search hold the caller to the project's own rights,
 * under the project's profile (P1-5).
 */
const ORG = 'org_a';
const WALLED = 'proj_walled';
const MINE = 'proj_mine';
const member: AuthUser = { user_id: 'user_member' };
const orgAdmin: AuthUser = { user_id: 'user_admin' };

const threads = {
  findByIdInOrg: vi.fn(async (threadId: string) => ({
    id: threadId,
    project_id: threadId === 'thr_org' ? null : WALLED,
    org_id: threadId === 'thr_org' ? ORG : null,
  })),
  listMessages: vi.fn(async () => ({ data: [] })),
  createMessage: vi.fn(async () => ({ id: 'msg_1' })),
};
const resources = { resolveResources: vi.fn(async () => ({ data: [] })) };
const memory = {
  distillThread: vi.fn(async () => ({ status: 'written' })),
  unifiedSearch: vi.fn(async () => ({
    data: [
      { source: 'attachments', job_id: 'job_walled', project_id: WALLED, name: 'plan.md' },
      { source: 'events', event_id: 'evt_walled', project_id: WALLED },
      { source: 'events', event_id: 'evt_mine', project_id: MINE },
      { source: 'docs', path: '/handbook/intro.md' },
    ],
  })),
};

function controllers() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  const scoped = new ScopedAccessService({ isEnabled: () => true } as never, access, rbac, security);
  const ctor = <T>(Type: new (...args: never[]) => T, ...args: unknown[]) => new (Type as new (...a: unknown[]) => T)(...args);
  return {
    threads: ctor(OrgThreadsController, threads, rbac),
    resources: ctor(ResourcesController, resources, scoped, rbac),
    memory: ctor(AgentMemoryController, memory, scoped, rbac),
  };
}

function seed(profile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme');
  store.addProject(WALLED, ORG, 'walled', profile);
  store.addProject(MINE, ORG, 'mine', profile);
  store.joinOrg(member.user_id, ORG, 'member');
  store.joinProject(member.user_id, MINE, 'member');
  store.joinOrg(orgAdmin.user_id, ORG, 'admin');
  // Org docs come from an org-wide binding; it says nothing about projects.
  store.bind({
    org_id: ORG, principal_id: member.user_id, permissions: ['orgdocs:read', 'orgdocs:write'],
    scope_json: { orgdocs: { allow_prefixes: ['/**'] } },
  });
  store.addResource('jobs', 'job_walled', WALLED);
  store.addResource('threads', 'thr_walled', WALLED);
}

const attachment = { uris: ['job_attachments:/job_walled/plan.md'], include_content: true };

describe('org routes that reach a project resource (P1-5)', () => {
  beforeEach(() => vi.clearAllMocks());

  describe('under a strict project', () => {
    beforeEach(() => seed('strict'));

    it('refuse a project thread to an org member with no rights on the project', async () => {
      const c = controllers();

      await expect(c.threads.show(ORG, 'thr_walled', member)).rejects.toBeInstanceOf(ForbiddenException);
      await expect(c.threads.listMessages(ORG, 'thr_walled', undefined, undefined, member)).rejects.toBeInstanceOf(ForbiddenException);
      await expect(c.threads.postMessage(ORG, 'thr_walled', { body: 'hi' } as never, member)).rejects.toBeInstanceOf(ForbiddenException);
      expect(threads.createMessage).not.toHaveBeenCalled();
    });

    it('serve org threads, and project threads to org admins', async () => {
      const c = controllers();

      await expect(c.threads.show(ORG, 'thr_org', member)).resolves.toMatchObject({ id: 'thr_org' });
      await expect(c.threads.show(ORG, 'thr_walled', orgAdmin)).resolves.toMatchObject({ id: 'thr_walled' });
    });

    it('refuse a job attachment of the project', async () => {
      const c = controllers();

      await expect(c.resources.resolve(ORG, attachment as never, member, undefined)).rejects.toBeInstanceOf(ForbiddenException);
      expect(resources.resolveResources).not.toHaveBeenCalled();
      await expect(c.resources.resolve(ORG, attachment as never, orgAdmin, undefined)).resolves.toBeDefined();
    });

    it('refuse distilling a thread of the project', async () => {
      const c = controllers();

      await expect(c.memory.distillThread(ORG, 'thr_walled', {}, member, undefined)).rejects.toBeInstanceOf(ForbiddenException);
      expect(memory.distillThread).not.toHaveBeenCalled();
    });

    it('leave the project\'s attachments and events out of org search', async () => {
      const c = controllers();

      const result = await c.memory.unifiedSearch(ORG, 'plan', undefined, 20, undefined, member, undefined) as { data: Array<Record<string, unknown>> };
      expect(result.data.map((row) => row.event_id ?? row.job_id ?? row.path)).toEqual(['evt_mine', '/handbook/intro.md']);
    });
  });

  describe('under an audit project', () => {
    beforeEach(() => seed('audit'));

    it('serve the org member and record each reach', async () => {
      const c = controllers();

      await expect(c.threads.show(ORG, 'thr_walled', member)).resolves.toMatchObject({ id: 'thr_walled' });
      await expect(c.resources.resolve(ORG, attachment as never, member, undefined)).resolves.toBeDefined();
      const result = await c.memory.unifiedSearch(ORG, 'plan', undefined, 20, undefined, member, undefined) as { data: unknown[] };
      expect(result.data).toHaveLength(4);
      expect(store.findings('access.implicit_project').map((f) => f.project_id)).toContain(WALLED);
    });
  });

  describe('under a legacy project', () => {
    beforeEach(() => seed('legacy'));

    it('change nothing and record nothing', async () => {
      const c = controllers();

      await expect(c.threads.postMessage(ORG, 'thr_walled', { body: 'hi' } as never, member)).resolves.toBeDefined();
      await expect(c.resources.resolve(ORG, attachment as never, member, undefined)).resolves.toBeDefined();
      await expect(c.memory.distillThread(ORG, 'thr_walled', {}, member, undefined)).resolves.toBeDefined();
      expect(store.findings()).toEqual([]);
    });
  });
});
