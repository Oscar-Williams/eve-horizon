import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { resolveProjectSecrets } from '../secret-client.js';

// The resolve names the job it delivers secrets to, so the API can judge the
// job's secret binding (rule secrets.unbound_job).

const originalEnv = { ...process.env };
let fetchMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  process.env.EVE_API_URL = 'http://api.eve.test';
  process.env.EVE_INTERNAL_API_KEY = 'internal-key';
  fetchMock = vi.fn(async () => new Response(JSON.stringify({ data: [] }), { status: 200 }));
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  process.env = { ...originalEnv };
  vi.unstubAllGlobals();
});

describe('resolveProjectSecrets', () => {
  it('sends the job and its harness when resolving for a job', async () => {
    await resolveProjectSecrets('proj_shop', { userId: 'user_alice', jobId: 'job_1', harness: 'claude' } as never);

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toEqual({ project_id: 'proj_shop', user_id: 'user_alice', job_id: 'job_1', harness: 'claude' });
  });

  it('sends only the project for a resolve that is not for a job', async () => {
    await resolveProjectSecrets('proj_shop');

    const body = JSON.parse(fetchMock.mock.calls[0][1].body);
    expect(body).toEqual({ project_id: 'proj_shop' });
  });
});
