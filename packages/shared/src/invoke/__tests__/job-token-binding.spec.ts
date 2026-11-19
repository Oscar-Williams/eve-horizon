import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation } from '../../types/harness.js';
import { resolveInvocationJobToken } from '../eve-credentials.js';
import { mintJobAppLinkTokens } from '../app-link-tokens.js';

const fetchSpy = vi.fn();
const SAVED = { ...process.env };

function jsonResponse(body: unknown) {
  return { ok: true, status: 200, statusText: 'OK', json: async () => body } as Response;
}

const invocation = {
  jobId: 'shop-1',
  attemptId: 'att-run-1',
  projectId: 'proj_shop',
  text: 'review',
  workspacePath: '/tmp/ws',
} as HarnessInvocation;

beforeEach(() => {
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  process.env.EVE_API_URL = 'http://api.test';
  process.env.EVE_INTERNAL_API_KEY = 'internal-key';
  fetchSpy.mockReset();
  vi.stubGlobal('fetch', fetchSpy);
});

afterEach(() => {
  vi.unstubAllGlobals();
  process.env = { ...SAVED };
});

function body(call: number): Record<string, unknown> {
  return JSON.parse(fetchSpy.mock.calls[call][1].body as string);
}

describe('tokens minted for a running job', () => {
  it('binds the job token to the attempt, so it stops working when the attempt ends', async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ access_token: 'job-token', token_type: 'bearer', expires_at: 1 }));

    await resolveInvocationJobToken(invocation, undefined, ['jobs:read']);

    expect(fetchSpy.mock.calls[0][0]).toBe('http://api.test/internal/auth/mint-job-token');
    expect(body(0)).toMatchObject({ job_id: 'shop-1', attempt_id: 'att-run-1' });
  });

  it("binds each app-link token to the job's attempt and returns them for the harness env", async () => {
    fetchSpy.mockResolvedValue(jsonResponse({ access_token: 'link-token', token_type: 'bearer', expires_at: 2 }));

    const links = await mintJobAppLinkTokens(invocation, [
      { name: 'shop', alias: 'shop', subscription_id: 'als_shop', base_url: 'https://shop.example', producer_env: 'prod' },
    ]);

    expect(fetchSpy.mock.calls[0][0]).toBe('http://api.test/internal/auth/mint-app-link-token');
    expect(body(0)).toMatchObject({
      subscription_id: 'als_shop', consumer_principal: 'job:shop-1', producer_env: 'prod', attempt_id: 'att-run-1',
    });
    expect(links).toEqual([
      expect.objectContaining({ alias: 'shop', origin: 'app_link', type: 'openapi', token: 'link-token' }),
    ]);
  });
});
