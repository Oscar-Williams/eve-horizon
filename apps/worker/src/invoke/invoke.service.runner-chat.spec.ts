import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation, PreparedAgentJob } from '@eve/shared';

/**
 * Chat replies from a job the worker runs. A chat job (label `chat`, a
 * `thread_id` hint) relays its `eve-message` blocks to the originating chat
 * thread as progress, as the agent runtime's inline path does: in the
 * worker's own process through the internal chat delivery route, and in a
 * runner pod (no internal key) through its attempt's thread-messages route,
 * with the same thread, text and agent. The final result is delivered by the
 * orchestrator from the attempt's result text, whichever path ran the job.
 */
const ENV = ['EVE_RUNTIME', 'EVE_API_URL', 'EVE_INTERNAL_CORE_KEY', 'DATABASE_URL'];
const saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
const fetches: Array<{ url: string; body: Record<string, unknown> }> = [];

beforeEach(() => {
  process.env.EVE_API_URL = 'http://eve-api.test';
  process.env.EVE_INTERNAL_CORE_KEY = 'core-key-for-test';
  process.env.DATABASE_URL = 'postgres://eve@db/eve';
  delete process.env.EVE_RUNTIME;
  fetches.length = 0;
  vi.stubGlobal('fetch', vi.fn(async (url: string, init?: { body?: string }) => {
    fetches.push({ url, body: init?.body ? JSON.parse(init.body) : {} });
    if (url.endsWith('/secrets/resolve')) return Response.json({ data: [] });
    if (url.endsWith('/mint-job-token')) return Response.json({ access_token: 'job-token-a', token_type: 'bearer', expires_at: 0 });
    return Response.json({ delivered: true });
  }));
});
afterEach(() => {
  vi.unstubAllGlobals();
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

const invocation = {
  jobId: 'shop-1', attemptId: '00000000-0000-0000-0000-00000000000a', projectId: 'proj_shop', agentId: 'agent_review',
  text: 'hello', harness: 'claude', repoUrl: 'https://git.example.com/acme/shop.git', workspacePath: '/tmp/eve-chat-test',
} as unknown as HarnessInvocation;

const CHAT_JOB = { id: 'shop-1', project_id: 'proj_shop', phase: 'active', actor_user_id: 'user_alice', labels: ['chat', 'agent:agent_review'], hints: { thread_id: 'thr_chat' } };

async function relayProgress(service: unknown): Promise<void> {
  const relay = await (service as { createMessageRelay(inv: HarnessInvocation): Promise<{ processLine(line: string): Promise<void> }> })
    .createMessageRelay(invocation);
  for (const line of ['```eve-message', '{"kind":"progress","body":"Halfway through the review"}', '```']) {
    await relay.processLine(line);
  }
}

async function workerService() {
  const { InvokeService } = await import('./invoke.service.js');
  const db = Object.assign(vi.fn(async (strings: TemplateStringsArray) => {
    const sql = strings.join('?');
    if (sql.includes('FROM jobs')) return [{ hints: CHAT_JOB.hints, labels: CHAT_JOB.labels, project_id: 'proj_shop' }];
    if (sql.includes('FROM threads')) return [{ project_id: 'proj_shop' }];
    return [];
  }), { json: (v: unknown) => v });
  const service = new InvokeService(db as never);
  const inner = service as unknown as Record<string, unknown>;
  inner.jobs = { findById: vi.fn(async () => CHAT_JOB), updateRuntimeMeta: vi.fn(), markExecutionStarted: vi.fn() };
  inner.projects = { findById: vi.fn(async () => ({ id: 'proj_shop', org_id: 'org_acme' })) };
  inner.logs = { appendLog: vi.fn(), listLogs: vi.fn(async () => []) };
  return service;
}

describe('chat replies from the worker path', () => {
  it("sends the job's chat thread to the runner in the submit", async () => {
    const service = await workerService();
    const prepared = await (service as unknown as { prepareAgentJob(inv: HarnessInvocation): Promise<PreparedAgentJob> }).prepareAgentJob(invocation);
    expect(prepared.chat).toEqual({ thread_id: 'thr_chat' });
  });

  it('relays progress to the chat thread in the worker process, as the inline path does', async () => {
    await relayProgress(await workerService());
    expect(fetches.filter((f) => f.url.includes('/chat/deliver'))).toEqual([{
      url: 'http://eve-api.test/internal/projects/proj_shop/chat/deliver',
      body: { job_id: 'shop-1', thread_id: 'thr_chat', text: 'Halfway through the review', agent_id: 'agent_review', progress: true },
    }]);
  });

  it('relays the same progress from a runner pod through its thread-messages route', async () => {
    const { InvokeService } = await import('./invoke.service.js');
    const client = {
      deliverChatProgress: vi.fn(async () => undefined),
      createThreadMessage: vi.fn(async () => undefined),
      emitEvent: vi.fn(async () => undefined),
      updateRuntimeMeta: vi.fn(async () => undefined),
    };
    const prepared = { invocation, secrets: [], chat: { thread_id: 'thr_chat' }, relay: { jobs: {}, threads: {} } } as unknown as PreparedAgentJob;
    await relayProgress(InvokeService.forRunner(prepared, client as never, { appendLog: () => undefined }));
    expect(client.deliverChatProgress).toHaveBeenCalledWith({ thread_id: 'thr_chat', text: 'Halfway through the review', agent_id: 'agent_review' });
    expect(fetches.filter((f) => f.url.includes('/internal/'))).toEqual([]);
  });

  it('relays nothing to chat for a job that is not a chat job', async () => {
    const { InvokeService } = await import('./invoke.service.js');
    const client = { deliverChatProgress: vi.fn(async () => undefined), createThreadMessage: vi.fn(async () => undefined) };
    const prepared = { invocation, secrets: [], chat: null, relay: { jobs: {}, threads: {} } } as unknown as PreparedAgentJob;
    await relayProgress(InvokeService.forRunner(prepared, client as never, { appendLog: () => undefined }));
    expect(client.deliverChatProgress).not.toHaveBeenCalled();
  });
});
