import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, HttpException } from '@nestjs/common';
import { AttemptsRunnerController } from './attempts.runner.controller';
import { RunnerAttemptsService } from './runner-attempts.service';
import { ChatInternalController } from '../chat/chat.internal.controller';

/**
 * Chat progress from a runner pod. A chat job's runner relays its
 * eve-message progress through the attempt's thread-messages route; the API
 * delivers it to the originating chat thread and provider with the same call
 * the inline path's internal delivery route makes. Only the job's own chat
 * thread, and at most as often as the relay allows: job code holds the
 * same token.
 */
const m = vi.hoisted(() => ({
  jobs: {} as Record<string, Record<string, unknown>>,
  progress: { count: 0, last: null as Date | null },
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    jobQueries: vi.fn(() => ({
      getTokenLiveness: vi.fn(async () => ({ phase: 'active', running_attempt_id: 'att-a' })),
      findById: vi.fn(async (id: string) => m.jobs[id] ?? null),
    })),
    threadQueries: vi.fn(() => ({ findById: vi.fn(async () => ({ project_id: 'proj_shop' })) })),
    threadMessageQueries: vi.fn(() => ({ create: vi.fn(async () => ({})) })),
  };
});

const TOKEN = { type: 'job', job_id: 'shop-1', attempt_id: 'att-a', project_id: 'proj_shop', org_id: 'org_acme', user_id: 'user_alice' };
const auth = { verifyJobToken: vi.fn(() => TOKEN) };
const db = Object.assign(vi.fn(async () => [{ count: m.progress.count, last: m.progress.last }]), { json: (v: unknown) => v });

function setup() {
  const chat = { deliverChatResult: vi.fn(async () => ({ delivered: true })) };
  const service = new RunnerAttemptsService(auth as never, db as never, {} as never, { decide: vi.fn() } as never, async () => ({ keys: [] }), chat as never);
  return { runner: new AttemptsRunnerController(service), chat };
}

const progress = (thread = 'thr_chat') => ({
  thread_id: thread, body: 'Halfway through the review', actor_type: 'agent', actor_id: 'agent_review', chat_progress: true,
});

beforeEach(() => {
  m.jobs = {
    'shop-1': { id: 'shop-1', project_id: 'proj_shop', parent_id: 'lead-1', labels: ['chat'], hints: { thread_id: 'thr_chat' } },
    'lead-1': { id: 'lead-1', project_id: 'proj_shop', hints: { coordination: { thread_id: 'thr_coord' } } },
  };
  m.progress = { count: 0, last: null };
});

describe('chat progress from a runner pod', () => {
  it('delivers it with the same call as the inline path', async () => {
    const { runner, chat } = setup();
    await runner.createThreadMessage('shop-1', 'att-a', 'Bearer token-a', progress());

    const inlineChat = { deliverChatResult: vi.fn(async () => ({ delivered: true })) };
    await new ChatInternalController(inlineChat as never).deliverOutbound('proj_shop', {
      job_id: 'shop-1', thread_id: 'thr_chat', text: 'Halfway through the review', agent_id: 'agent_review', progress: true,
    } as never);

    expect(chat.deliverChatResult).toHaveBeenCalledTimes(1);
    expect(chat.deliverChatResult.mock.calls[0]).toEqual(inlineChat.deliverChatResult.mock.calls[0]);
  });

  it("delivers only to the job's own chat thread, and only for a chat job", async () => {
    const { runner, chat } = setup();
    await expect(runner.createThreadMessage('shop-1', 'att-a', 'Bearer token-a', progress('thr_coord')))
      .rejects.toBeInstanceOf(ForbiddenException);
    m.jobs['shop-1'].labels = ['nightly'];
    await expect(runner.createThreadMessage('shop-1', 'att-a', 'Bearer token-a', progress()))
      .rejects.toBeInstanceOf(ForbiddenException);
    expect(chat.deliverChatResult).not.toHaveBeenCalled();
  });

  it('holds progress to the relay limits: at most ten per job, thirty seconds apart', async () => {
    const { runner, chat } = setup();
    m.progress = { count: 10, last: new Date(Date.now() - 60_000) };
    await expect(runner.createThreadMessage('shop-1', 'att-a', 'Bearer token-a', progress())).rejects.toBeInstanceOf(HttpException);
    m.progress = { count: 2, last: new Date(Date.now() - 5_000) };
    await expect(runner.createThreadMessage('shop-1', 'att-a', 'Bearer token-a', progress())).rejects.toMatchObject({ status: 429 });
    expect(chat.deliverChatResult).not.toHaveBeenCalled();
  });
});
