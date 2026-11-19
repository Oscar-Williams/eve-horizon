import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ChatService } from './chat.service.js';
import { RbacService } from '../auth/rbac.service.js';
import { SecurityService } from '../security/security.service.js';
import type { JobsService } from '../jobs/jobs.service.js';
import type { AuthUser } from '../auth/auth.types.js';
import { accessStore as store } from '../auth/__tests__/access-store.js';

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('../auth/__tests__/access-store.js');
  return {
    ...actual,
    ...accessStore.queries,
    agentConfigQueries: () => ({
      findLatestByProject: async () => ({
        parsed_routes: [{ id: 'all', match: '.*', target: 'agent:agent_a' }],
        chat_yaml: '',
      }),
    }),
    agentQueries: () => ({
      listByProject: async () => [{ id: 'agent_a', slug: 'helper', harness_profile: null }],
    }),
  };
});

const ORG = 'org_a';
const PROJECT = 'proj_a';

/** Chat with its thread bookkeeping stubbed: these tests are about who may start work. */
function chatService() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const create = vi.fn(async () => ({ id: 'job_1' }));
  const dispatch = vi.fn(async () => ['job_route']);
  const service = new ChatService(store.db as never, { create } as unknown as JobsService, rbac);
  const priv = service as unknown as Record<string, unknown>;
  priv.recordThreadAndEvent = vi.fn(async () => ({ thread: { id: 'thr_1', key: 'k' }, eventId: 'evt_1' }));
  priv.setThreadContinuation = vi.fn(async () => undefined);
  priv.buildThreadContext = vi.fn(async () => null);
  priv.resolveHarnessProfile = vi.fn(async () => ({ harness: undefined, harness_options: undefined }));
  priv.getAgentContextHints = vi.fn(() => ({}));
  priv.getAgentAppApisHint = vi.fn(() => ({}));
  priv.dispatchRouteTarget = dispatch;
  return { service, create, dispatch };
}

/** A gateway message: the sender is whoever the gateway mapped to an Eve user, if anyone. */
function gatewayMessage(eveUserId?: string) {
  return {
    provider: 'slack',
    account_id: 'T1',
    channel_id: 'C100',
    user_id: 'U_EXT',
    text: 'hello',
    metadata: eveUserId ? { eve_user_id: eveUserId } : {},
  };
}

function seed(profile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme');
  store.addProject(PROJECT, ORG, 'alpha', profile);
  store.joinOrg('user_member', ORG, 'member');
  store.joinOrg('user_admin', ORG, 'admin');
  store.joinOrg('user_pm', ORG, 'member');
  store.joinProject('user_pm', PROJECT, 'member');
}

describe('chat starts agent work only for senders with project rights (P1-5)', () => {
  describe('under a strict project', () => {
    beforeEach(() => seed('strict'));

    it('refuses a sender the gateway could not map to an Eve user', async () => {
      const { service, create } = chatService();

      const result = await service.routeMessageToAgent(PROJECT, 'agent_a', gatewayMessage());

      expect(result).toMatchObject({ denied: true, job_ids: [] });
      expect(create).not.toHaveBeenCalled();
      expect(store.findings('chat.sender_rights')[0]).toMatchObject({ profile: 'strict', project_id: PROJECT, actor_type: 'none' });
    });

    it('refuses an org member with no rights on the project, on agent and route dispatch alike', async () => {
      const { service, create, dispatch } = chatService();

      await expect(service.routeMessageToAgent(PROJECT, 'agent_a', gatewayMessage('user_member')))
        .resolves.toMatchObject({ denied: true, job_ids: [] });
      await expect(service.routeMessage(PROJECT, gatewayMessage('user_member')))
        .resolves.toMatchObject({ denied: true, job_ids: [] });
      expect(create).not.toHaveBeenCalled();
      expect(dispatch).not.toHaveBeenCalled();
    });

    it('starts work for a project member and an org admin', async () => {
      const { service, create, dispatch } = chatService();

      await expect(service.routeMessageToAgent(PROJECT, 'agent_a', gatewayMessage('user_pm')))
        .resolves.toMatchObject({ job_ids: ['job_1'] });
      await expect(service.routeMessage(PROJECT, gatewayMessage('user_admin')))
        .resolves.toMatchObject({ job_ids: ['job_route'] });
      expect(create).toHaveBeenCalledTimes(1);
      expect(dispatch).toHaveBeenCalledTimes(1);
      expect(store.findings('chat.sender_rights')).toEqual([]);
    });

    it('judges an authenticated API caller on their own rights', async () => {
      const { service, create } = chatService();
      const caller: AuthUser = { user_id: 'user_member' };

      await expect(service.routeMessageToAgent(PROJECT, 'agent_a', gatewayMessage(), {}, { user: caller }))
        .resolves.toMatchObject({ denied: true });
      expect(create).not.toHaveBeenCalled();
    });
  });

  describe('under an audit project', () => {
    beforeEach(() => seed('audit'));

    it('starts the work and records what strict would refuse', async () => {
      const { service, create } = chatService();

      await expect(service.routeMessageToAgent(PROJECT, 'agent_a', gatewayMessage()))
        .resolves.toMatchObject({ job_ids: ['job_1'] });
      expect(create).toHaveBeenCalledTimes(1);
      expect(store.findings('chat.sender_rights')[0]).toMatchObject({ profile: 'audit', project_id: PROJECT });
    });
  });

  describe('under a legacy project', () => {
    beforeEach(() => seed('legacy'));

    it('starts the work and records nothing', async () => {
      const { service, create } = chatService();

      await expect(service.routeMessageToAgent(PROJECT, 'agent_a', gatewayMessage()))
        .resolves.toMatchObject({ job_ids: ['job_1'] });
      expect(create).toHaveBeenCalledTimes(1);
      expect(store.findings()).toEqual([]);
    });
  });
});
