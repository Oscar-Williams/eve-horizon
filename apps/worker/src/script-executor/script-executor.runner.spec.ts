import { afterEach, describe, expect, it, vi } from 'vitest';
import { ScriptExecutorService } from './script-executor.service.js';

const runner = vi.hoisted(() => ({ dispatch: vi.fn() }));
vi.mock('../invoke/runner-dispatch.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../invoke/runner-dispatch.js')>()),
  dispatchToRunnerPod: runner.dispatch,
}));

const original = {
  runtime: process.env.EVE_RUNTIME,
  enabled: process.env.EVE_SCRIPT_K8S_RUNNER,
  selfTerminate: process.env.EVE_RUNNER_SELF_TERMINATE,
  initMounted: process.env.EVE_TOOLCHAIN_INIT_MOUNTED,
  apiUrl: process.env.EVE_API_URL,
  coreKey: process.env.EVE_INTERNAL_CORE_KEY,
  databaseUrl: process.env.DATABASE_URL,
};
afterEach(() => {
  for (const [key, value] of Object.entries({ EVE_RUNTIME: original.runtime,
    EVE_SCRIPT_K8S_RUNNER: original.enabled, EVE_RUNNER_SELF_TERMINATE: original.selfTerminate,
    EVE_TOOLCHAIN_INIT_MOUNTED: original.initMounted, EVE_API_URL: original.apiUrl,
    EVE_INTERNAL_CORE_KEY: original.coreKey, DATABASE_URL: original.databaseUrl })) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  runner.dispatch.mockReset();
  vi.unstubAllGlobals();
});

/** A db stub that answers the project lookup and nothing else. */
function projectDb() {
  return Object.assign(vi.fn(async (strings: TemplateStringsArray) => (strings.join('?').includes('FROM projects p')
    ? [{ repo_url: 'https://github.com/acme/shop.git', slug: 'shop', org_slug: 'acme', branch: 'main' }]
    : [])), { json: (v: unknown) => v });
}

describe('script runner dispatch', () => {
  it('prepares the step in the worker and submits only what the runner needs', async () => {
    process.env.EVE_RUNTIME = 'k8s';
    process.env.EVE_SCRIPT_K8S_RUNNER = 'true';
    process.env.EVE_API_URL = 'http://eve-api.test';
    process.env.EVE_INTERNAL_CORE_KEY = 'core-key-for-test';
    process.env.DATABASE_URL = 'postgres://eve@db/eve';
    delete process.env.EVE_RUNNER_SELF_TERMINATE;
    const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init: { body?: string }) => {
      requests.push({ url, body: init?.body ? JSON.parse(init.body) : {} });
      if (url.endsWith('/secrets/resolve')) {
        return Response.json({ data: [
          { key: 'GITHUB_TOKEN', value: 'ghp_shop', type: 'github_token' },
          { key: 'APP_DB_URL', value: 'postgres://app', type: 'env_var' },
          { key: 'STRIPE_KEY', value: 'sk_live_shop', type: 'env_var' },
        ] });
      }
      if (url.endsWith('/mint-job-token')) return Response.json({ access_token: 'job-token-1', token_type: 'bearer', expires_at: 0 });
      return new Response('not found', { status: 404 });
    }));
    const service = new ScriptExecutorService(projectDb() as never);
    (service as unknown as { jobs: unknown }).jobs = { findById: vi.fn().mockResolvedValue({
      id: 'job_1', project_id: 'proj_1', execution_type: 'script', script_command: 'echo test', phase: 'active',
      env_overrides: { DATABASE_URL: '${secret.APP_DB_URL}' }, hints: { toolchains: ['python', 'browser'] },
    }), updateRuntimeMeta: vi.fn(), markExecutionStarted: vi.fn() };
    runner.dispatch.mockResolvedValue({ success: true, exitCode: 0,
      resultReport: { success: true, exit_code: 0, stdout: 'done', stderr: '' } });

    const result = await service.execute('job_1', 'att_1');
    expect(result).toMatchObject({ success: true, stdout: 'done' });
    const [submit] = runner.dispatch.mock.calls[0] as [Record<string, any>];
    expect(submit).toMatchObject({ kind: 'script', job_id: 'job_1', attempt_id: 'att_1', project_id: 'proj_1',
      job_token: 'job-token-1', script: { command: 'echo test', toolchains: ['python', 'browser'] } });
    expect(submit.script.secrets).toEqual([
      expect.objectContaining({ key: 'GITHUB_TOKEN', clone_only: true }),
      expect.objectContaining({ key: 'APP_DB_URL' }),
    ]);
    expect(JSON.stringify(submit)).not.toContain('core-key-for-test');
    expect(requests.find((r) => r.url.endsWith('/mint-job-token'))?.body).toMatchObject({ job_id: 'job_1', attempt_id: 'att_1' });

    runner.dispatch.mockResolvedValueOnce({ success: false, exitCode: 1,
      error: 'toolchain_unavailable: browser init image pull failed' });
    const startupFailure = await service.execute('job_1', 'att_2');
    expect(startupFailure).toMatchObject({ success: false, errorCode: 'toolchain_unavailable' });
    process.env.EVE_RUNNER_SELF_TERMINATE = '1';
    expect(service.shouldDispatchToRunner()).toBe(false);
  });

  it('keeps pulled init image IDs through script provisioning and failure writes', async () => {
    process.env.EVE_TOOLCHAIN_INIT_MOUNTED = 'true';
    const meta: Record<string, unknown> = { toolchains: { requested: ['browser'],
      image_ids: { browser: 'docker-pullable://browser@sha256:abc' } } };
    const db = vi.fn(async () => [{ runtime_meta: meta }]);
    const service = new ScriptExecutorService(db as never);
    const updateRuntimeMeta = vi.fn(async (_id: string, value: Record<string, unknown>) => Object.assign(meta, value));
    (service as unknown as { jobs: unknown }).jobs = { updateRuntimeMeta };
    const write = (service as unknown as { updateScriptToolchainMeta: (id: string, value: Record<string, unknown>) => Promise<void> }).updateScriptToolchainMeta.bind(service);
    await write('00000000-0000-0000-0000-000000000001', { requested: ['browser'], resolved: ['browser'] });
    await write('00000000-0000-0000-0000-000000000001', { requested: ['browser'],
      error_code: 'toolchain_unavailable', source: 'unavailable' });
    expect(meta.toolchains).toMatchObject({ image_ids: { browser: 'docker-pullable://browser@sha256:abc' },
      error_code: 'toolchain_unavailable' });
  });
});
