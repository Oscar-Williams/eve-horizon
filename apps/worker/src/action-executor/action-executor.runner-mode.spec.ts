import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException } from '@nestjs/common';

/**
 * isolation.runner_mode for steps the worker used to run in its own process:
 * `action: run` runs in a runner pod (through the script runner's handler),
 * and a legacy pipeline-runner `run` step is refused (400, "use a script:
 * step"), under the project's strict profile and whenever the instance sets
 * EVE_RUNNER_PODS_ONLY. Under audit they run as before and are recorded.
 */
const m = vi.hoisted(() => ({
  mode: { profile: 'strict', podsOnly: false, required: true },
  findings: [] as Array<Record<string, unknown>>,
  dispatched: [] as Array<Record<string, any>>,
}));
vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  runnerModeFor: vi.fn(async () => m.mode),
  recordRunnerModeFinding: vi.fn(async (_db: unknown, finding: Record<string, unknown>) => { m.findings.push(finding); }),
}));
vi.mock('../invoke/runner-dispatch.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../invoke/runner-dispatch.js')>()),
  dispatchToRunnerPod: vi.fn(async (submit: Record<string, any>) => {
    m.dispatched.push(submit);
    return { success: true, exitCode: 0, resultReport: { success: true, exit_code: 0, stdout: 'ok\n', stderr: '' } };
  }),
}));

import { ActionExecutorService } from './action-executor.service.js';
import { PipelineRunnerService } from '../pipeline-runner/pipeline-runner.service.js';

const ENV = ['EVE_RUNTIME', 'EVE_RUNNER_PODS_ONLY', 'EVE_API_URL', 'EVE_INTERNAL_CORE_KEY', 'DATABASE_URL'];
const saved = Object.fromEntries(ENV.map((k) => [k, process.env[k]]));

beforeEach(() => {
  m.findings = []; m.dispatched = [];
  process.env.EVE_RUNTIME = 'k8s';
  process.env.EVE_API_URL = 'http://eve-api.test';
  process.env.EVE_INTERNAL_CORE_KEY = 'core-key-for-test';
  process.env.DATABASE_URL = 'postgres://eve@db/eve';
  delete process.env.EVE_RUNNER_PODS_ONLY;
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.endsWith('/secrets/resolve')) return Response.json({ data: [] });
    if (url.endsWith('/mint-job-token')) return Response.json({ access_token: 'job-token-1', token_type: 'bearer', expires_at: 0 });
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

function projectDb() {
  return Object.assign(vi.fn(async (strings: TemplateStringsArray) => (strings.join('?').includes('FROM projects p')
    ? [{ repo_url: 'https://git.example.com/acme/shop.git', slug: 'shop', org_slug: 'acme', branch: 'main' }]
    : [])), { json: (v: unknown) => v });
}

function actionExecutor() {
  const service = new ActionExecutorService(projectDb() as never, {} as never, {} as never);
  const inner = service as unknown as Record<string, unknown>;
  inner.projects = { findById: vi.fn(async () => ({ id: 'proj_shop', org_id: 'org_acme', repo_url: 'https://git.example.com/acme/shop.git' })) };
  inner.jobs = {
    findById: vi.fn(async () => ({ id: 'shop-1', project_id: 'proj_shop', phase: 'active', env_overrides: null, hints: {} })),
    updateRuntimeMeta: vi.fn(async () => ({})),
    markExecutionStarted: vi.fn(async () => undefined),
  };
  inner.logs = { appendLog: vi.fn(async () => undefined) };
  return service as unknown as { handleRun(attemptId: string, jobId: string, projectId: string, input: Record<string, unknown>): Promise<Record<string, unknown>> };
}

const runInput = { command: 'npm test', git_sha: '0123456789abcdef0123456789abcdef01234567' };

describe('action: run', () => {
  it('runs in a runner pod under strict', async () => {
    m.mode = { profile: 'strict', podsOnly: false, required: true };
    const output = await actionExecutor().handleRun('att-1', 'shop-1', 'proj_shop', runInput);
    expect(output).toMatchObject({ command: 'npm test', exit_code: 0 });
    expect(m.dispatched).toEqual([expect.objectContaining({
      kind: 'script', job_id: 'shop-1', attempt_id: 'att-1', job_token: 'job-token-1',
      script: expect.objectContaining({ command: 'npm test', timeout_code: 'action_run_timeout',
        git_ref: { ref: runInput.git_sha, source: 'explicit' } }),
    })]);
  });

  it('runs in a runner pod under the instance switch, whatever the profile', async () => {
    m.mode = { profile: 'audit', podsOnly: true, required: true };
    await actionExecutor().handleRun('att-1', 'shop-1', 'proj_shop', runInput);
    expect(m.dispatched).toHaveLength(1);
  });

  it('is refused outside Kubernetes under strict', async () => {
    delete process.env.EVE_RUNTIME;
    m.mode = { profile: 'strict', podsOnly: false, required: true };
    await expect(actionExecutor().handleRun('att-1', 'shop-1', 'proj_shop', runInput)).rejects.toThrow(/strict needs runner pods/);
    expect(m.dispatched).toEqual([]);
  });
});

describe('legacy pipeline-runner run steps', () => {
  function legacyRun() {
    const service = new PipelineRunnerService(projectDb() as never, {} as never);
    return (service as unknown as { handleRun(stepId: string, run: Record<string, unknown>, manifest: Record<string, unknown>, action: Record<string, unknown>): Promise<void> })
      .handleRun('step-1', { project_id: 'proj_shop', git_sha: runInput.git_sha, env_name: null }, {}, { command: 'npm test' });
  }

  it('is refused with a 400 under strict and under the instance switch', async () => {
    m.mode = { profile: 'strict', podsOnly: false, required: true };
    await expect(legacyRun()).rejects.toBeInstanceOf(BadRequestException);
    await expect(legacyRun()).rejects.toThrow(/use a `script:` step/);
    m.mode = { profile: 'legacy', podsOnly: true, required: true };
    await expect(legacyRun()).rejects.toBeInstanceOf(BadRequestException);
  });

  it('is recorded under audit', async () => {
    m.mode = { profile: 'audit', podsOnly: false, required: false };
    await legacyRun().catch(() => undefined);
    expect(m.findings).toEqual([expect.objectContaining({ projectId: 'proj_shop', detail: expect.objectContaining({ kind: 'legacy_run' }) })]);
  });
});
