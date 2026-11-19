import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation } from '@eve/shared';
import { InvokeService } from './invoke.service.js';

/**
 * In k8s the worker prepares an agent job and hands the runner pod everything
 * it needs in the submit body: the job's bound secrets (the clone credential
 * flagged clone_only), its attempt-bound job token and its prepared context.
 * The worker's own credentials never travel.
 */
const dispatch = vi.hoisted(() => ({ submits: [] as unknown[] }));
vi.mock('./runner-dispatch.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./runner-dispatch.js')>()),
  dispatchToRunnerPod: vi.fn(async (submit: unknown) => {
    dispatch.submits.push(submit);
    return { attemptId: 'att-a', success: true, exitCode: 0, resultText: 'done' };
  }),
}));

const ENV = ['EVE_RUNTIME', 'EVE_API_URL', 'EVE_INTERNAL_CORE_KEY', 'EVE_INTERNAL_API_KEY', 'DATABASE_URL'];
const saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));
const requests: Array<{ url: string; body: Record<string, unknown> }> = [];

beforeEach(() => {
  process.env.EVE_RUNTIME = 'k8s';
  process.env.EVE_API_URL = 'http://eve-api.test';
  process.env.EVE_INTERNAL_CORE_KEY = 'core-key-for-test';
  process.env.DATABASE_URL = 'postgres://eve:db-password-for-test@db/eve';
  delete process.env.EVE_INTERNAL_API_KEY;
  dispatch.submits = [];
  requests.length = 0;
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: { body?: string }) => {
    const body = init?.body ? JSON.parse(init.body) : {};
    requests.push({ url, body });
    if (url.endsWith('/internal/projects/proj_shop/secrets/resolve')) {
      return Response.json({ data: [
        { key: 'ANTHROPIC_API_KEY', value: 'sk-org', type: 'env_var', scope_type: 'org', scope_id: 'org_acme' },
        { key: 'GITHUB_TOKEN', value: 'ghp_shop', type: 'github_token', scope_type: 'project', scope_id: 'proj_shop', clone_only: true },
      ] });
    }
    if (url.endsWith('/internal/auth/mint-job-token')) {
      return Response.json({ access_token: 'job-token-a', token_type: 'bearer', expires_at: 0 });
    }
    return new Response('not found', { status: 404 });
  }));
});

afterEach(() => {
  vi.unstubAllGlobals();
  for (const [key, value] of Object.entries(saved)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

function service(): InvokeService {
  const db = Object.assign(vi.fn(async () => []), { json: (v: unknown) => v });
  const svc = new InvokeService(db as never);
  const inner = svc as unknown as Record<string, unknown>;
  inner.jobs = {
    findById: vi.fn(async (id: string) => ({ id, project_id: 'proj_shop', phase: 'active', actor_user_id: 'user_alice', hints: {} })),
    updateRuntimeMeta: vi.fn(async () => ({})),
    markExecutionStarted: vi.fn(async () => undefined),
  };
  inner.projects = { findById: vi.fn(async () => ({ id: 'proj_shop', org_id: 'org_acme' })) };
  inner.logs = { appendLog: vi.fn(async () => undefined), listLogs: vi.fn(async () => []) };
  return svc;
}

const invocation = {
  jobId: 'shop-1',
  attemptId: 'att-a',
  projectId: 'proj_shop',
  text: 'Review the shop',
  harness: 'claude',
  repoUrl: 'https://github.com/acme/shop.git',
  repoBranch: 'main',
  workspacePath: '/opt/eve/workspaces/att-a',
  data: { env_name: null, user_id: 'user_mallory' },
} as unknown as HarnessInvocation;

describe('agent job submit to a runner pod', () => {
  it("carries the job's bound secrets and attempt token, and none of the worker's credentials", async () => {
    const result = await service().execute(invocation);
    expect(result).toMatchObject({ success: true, resultText: 'done' });

    expect(dispatch.submits).toHaveLength(1);
    const submit = dispatch.submits[0] as Record<string, any>;
    expect(submit).toMatchObject({ kind: 'agent', job_id: 'shop-1', attempt_id: 'att-a', project_id: 'proj_shop', job_token: 'job-token-a' });
    expect(submit.agent.secrets).toEqual([
      expect.objectContaining({ key: 'ANTHROPIC_API_KEY' }),
      expect.objectContaining({ key: 'GITHUB_TOKEN', clone_only: true }),
    ]);
    const serialized = JSON.stringify(submit);
    expect(serialized).not.toContain('core-key-for-test');
    expect(serialized).not.toContain('db-password-for-test');

    const resolve = requests.find((r) => r.url.endsWith('/secrets/resolve'));
    expect(resolve?.body).toMatchObject({ project_id: 'proj_shop', job_id: 'shop-1', harness: 'claude', bound: true });
    expect(resolve?.body).not.toHaveProperty('user_id');
    const mint = requests.find((r) => r.url.endsWith('/mint-job-token'));
    expect(mint?.body).toMatchObject({ job_id: 'shop-1', attempt_id: 'att-a' });
  });
});
