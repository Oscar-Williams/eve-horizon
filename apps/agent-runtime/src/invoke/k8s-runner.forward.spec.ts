import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation } from '@eve/shared';
import { forwardInvocationToWorker } from './k8s-runner.js';

/**
 * The agent runtime in runner mode builds no pod of its own. It hands the
 * invocation to the worker, which prepares the job and runs it in a runner
 * pod (one dispatch path), and returns the worker's result.
 */
const spawn = vi.hoisted(() => vi.fn());
vi.mock('child_process', async (importOriginal) => ({ ...(await importOriginal<typeof import('node:child_process')>()), spawn }));

const invocation = { jobId: 'shop-1', attemptId: 'att-a', projectId: 'proj_shop', text: 'Review the shop' } as unknown as HarnessInvocation;

beforeEach(() => {
  vi.stubEnv('WORKER_URL', 'http://eve-worker.test:4749');
  vi.stubEnv('EVE_API_URL', 'http://eve-api.test');
  vi.stubEnv('EVE_INTERNAL_CORE_KEY', 'core-key');
  vi.stubEnv('EVE_K8S_POLL_INTERVAL_MS', '1');
  vi.stubEnv('DATABASE_URL', 'postgres://eve@db/eve');
});
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); spawn.mockReset(); });

describe('agent runtime runner mode', () => {
  it('forwards the invocation to the worker and creates no pod', async () => {
    const calls: Array<{ url: string; body?: unknown }> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: { body?: string }) => {
      calls.push({ url, body: init?.body ? JSON.parse(init.body) : undefined });
      if (url === 'http://eve-worker.test:4749/invoke') return new Response(JSON.stringify({ accepted: true }), { status: 202 });
      if (url.includes('/events')) {
        return Response.json({ data: [{ id: 'evt-1', type: 'runner.completed', payload_json: {
          attemptId: 'att-a', jobId: 'shop-1', result: { attemptId: 'att-a', success: true, exitCode: 0, resultText: 'done' } } }] });
      }
      throw new Error(`unexpected fetch ${url}`);
    }));

    const result = await forwardInvocationToWorker(invocation);

    expect(result).toMatchObject({ success: true, resultText: 'done' });
    expect(calls[0]).toEqual({ url: 'http://eve-worker.test:4749/invoke', body: invocation });
    expect(spawn).not.toHaveBeenCalled();
  });

  it('returns a failure when the worker refuses the job', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('busy', { status: 503 })));
    const result = await forwardInvocationToWorker(invocation);
    expect(result).toMatchObject({ success: false, error: expect.stringContaining('503') });
  });
});
