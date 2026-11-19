import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import type { NestFastifyApplication } from '@nestjs/platform-fastify';
import { createRunnerInboundKey } from '@eve/shared';
import { createRunnerApp } from './runner.app.js';

/**
 * The runner entrypoint serves one job. It starts with no database URL and no
 * internal key, loads no database module, answers /health from the process
 * alone, and takes one submit, authenticated by the inbound key whose hash
 * its pod carries. It pushes the result to the API with the job's own token.
 */
const PLATFORM = ['DATABASE_URL', 'EVE_INTERNAL_API_KEY', 'EVE_INTERNAL_CORE_KEY', 'EVE_RUNNER_SELF_TERMINATE'];
const saved = Object.fromEntries([...PLATFORM, 'EVE_RUNNER_INBOUND_KEY_SHA256'].map((k) => [k, process.env[k]]));
const inbound = createRunnerInboundKey();
const executor = { run: vi.fn(async (_submit: unknown, _client: unknown) => ({ success: true, exit_code: 0, result_text: 'done' })) };
const fetchMock = vi.fn(async () => new Response(null, { status: 201 }));
let app: NestFastifyApplication;

const submit = {
  kind: 'agent',
  job_id: 'shop-1',
  attempt_id: 'att-a',
  project_id: 'proj_shop',
  job_token: 'job-token-a',
  api_url: 'http://eve-api.test',
  agent: { invocation: { jobId: 'shop-1', attemptId: 'att-a', projectId: 'proj_shop', text: 'hello' }, secrets: [] },
};

beforeAll(async () => {
  for (const key of PLATFORM) delete process.env[key];
  process.env.EVE_RUNNER_INBOUND_KEY_SHA256 = inbound.sha256;
  vi.stubGlobal('fetch', fetchMock);
  app = await createRunnerApp({ executor, logger: false });
  await app.init();
  await app.getHttpAdapter().getInstance().ready();
});

afterAll(async () => {
  await app?.close();
  vi.unstubAllGlobals();
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

afterEach(() => {
  fetchMock.mockClear();
});

function inject(opts: { method: 'GET' | 'POST'; url: string; key?: string; body?: unknown }) {
  return app.getHttpAdapter().getInstance().inject({
    method: opts.method,
    url: opts.url,
    headers: opts.key ? { 'x-eve-runner-key': opts.key } : {},
    ...(opts.body ? { payload: opts.body as Record<string, unknown> } : {}),
  });
}

describe('runner entrypoint', () => {
  it('starts without a database and loads no database module', () => {
    expect(process.env.DATABASE_URL).toBeUndefined();
    expect(() => app.get('DB', { strict: false })).toThrow();
  });

  it('answers /health from the process alone', async () => {
    const res = await inject({ method: 'GET', url: '/health' });
    expect(res.statusCode).toBe(200);
  });

  it('refuses a submit without the inbound key', async () => {
    expect((await inject({ method: 'POST', url: '/runner/submit', body: submit })).statusCode).toBe(401);
    expect((await inject({ method: 'POST', url: '/runner/submit', key: 'not-the-key', body: submit })).statusCode).toBe(401);
    expect(executor.run).not.toHaveBeenCalled();
  });

  it('has no route but submit and health', async () => {
    expect((await inject({ method: 'POST', url: '/invoke', key: inbound.key, body: submit })).statusCode).toBe(404);
    expect((await inject({ method: 'POST', url: '/scripts/execute', key: inbound.key, body: submit })).statusCode).toBe(404);
  });

  it('runs one submitted job and pushes its result with the job token', async () => {
    const res = await inject({ method: 'POST', url: '/runner/submit', key: inbound.key, body: submit });
    expect(res.statusCode).toBe(202);
    await vi.waitFor(() => expect(fetchMock).toHaveBeenCalledWith(
      'http://eve-api.test/jobs/shop-1/attempts/att-a/runner/result',
      expect.objectContaining({ method: 'POST', headers: expect.objectContaining({ authorization: 'Bearer job-token-a' }) }),
    ));
    expect(executor.run).toHaveBeenCalledTimes(1);
    expect(executor.run.mock.calls[0][0]).toMatchObject({ job_id: 'shop-1', attempt_id: 'att-a' });

    const again = await inject({ method: 'POST', url: '/runner/submit', key: inbound.key, body: submit });
    expect(again.statusCode).toBe(409);
    expect(executor.run).toHaveBeenCalledTimes(1);
  });
});
