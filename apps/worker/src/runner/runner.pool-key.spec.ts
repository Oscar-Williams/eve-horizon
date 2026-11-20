import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { createHash } from 'node:crypto';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createRunnerApp } from './runner.app.js';

/**
 * A runner started from a warm pool carries no per-pod key: its template
 * carries the SHA-256 of the worker's pool key instead, and every submit must
 * present that key. A runner with neither hash takes no submit at all.
 */
const POOL_KEY = 'pool-key-for-test';
const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');
const ENV = ['EVE_RUNNER_INBOUND_KEY_SHA256', 'EVE_RUNNER_POOL_KEY_SHA256', 'EVE_RUNNER_SELF_TERMINATE'];
const saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));

const submit = {
  kind: 'agent',
  job_id: 'shop-1',
  attempt_id: 'att-a',
  project_id: 'proj_shop',
  job_token: 'job-token-a',
  api_url: 'http://eve-api.test',
  agent: { invocation: { jobId: 'shop-1', attemptId: 'att-a', projectId: 'proj_shop', text: 'hello' }, secrets: [] },
};
let app: NestFastifyApplication | null = null;
const executor = { run: vi.fn(async () => ({ success: true, exit_code: 0 })) };

async function runner(env: Record<string, string>) {
  for (const key of ENV) delete process.env[key];
  Object.assign(process.env, env);
  app = await createRunnerApp({ executor, selfCheck: async () => null, logger: false });
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
  return (key?: string) => app!.getHttpAdapter().getInstance().inject({
    method: 'POST', url: '/runner/submit', headers: key ? { 'x-eve-runner-key': key } : {}, payload: submit,
  });
}

beforeEach(() => {
  executor.run.mockClear();
  vi.stubGlobal('fetch', vi.fn(async () => new Response(null, { status: 201 })));
});
afterEach(async () => {
  await app?.close();
  app = null;
  vi.unstubAllGlobals();
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

describe('a warm-pool runner', () => {
  it('refuses a submit that does not present the pool key', async () => {
    const post = await runner({ EVE_RUNNER_POOL_KEY_SHA256: sha256(POOL_KEY) });
    expect((await post('any-key')).statusCode).toBe(401);
    expect((await post()).statusCode).toBe(401);
    expect(executor.run).not.toHaveBeenCalled();
  });

  it('takes a submit that presents the pool key', async () => {
    const post = await runner({ EVE_RUNNER_POOL_KEY_SHA256: sha256(POOL_KEY) });
    expect((await post(POOL_KEY)).statusCode).toBe(202);
  });

  it('takes no submit at all when it holds neither key hash', async () => {
    const post = await runner({});
    expect((await post('any-key')).statusCode).toBe(401);
    expect(executor.run).not.toHaveBeenCalled();
  });
});
