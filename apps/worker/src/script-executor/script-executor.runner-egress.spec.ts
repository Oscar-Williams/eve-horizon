import { afterEach, describe, expect, it, vi } from 'vitest';
import { ScriptExecutorService } from './script-executor.service.js';

// Dispatch brings the project's runner egress policies in line with its
// profile before the runner pod starts (egress.default_deny).
const calls = vi.hoisted(() => [] as string[]);
vi.mock('../invoke/k8s-runner.js', () => ({
  runInvocationInK8s: vi.fn(async () => {
    calls.push('runner');
    return { success: true, exitCode: 0, runnerEventObserved: true, resultJson: { stdout: '', stderr: '', exit_code: 0 } };
  }),
}));
vi.mock('../network/runner-egress.js', () => ({
  ensureRunnerEgress: vi.fn(async (projectId: string) => { calls.push(`egress:${projectId}`); }),
}));

const original = { runtime: process.env.EVE_RUNTIME, enabled: process.env.EVE_SCRIPT_K8S_RUNNER };
afterEach(() => {
  for (const [key, value] of Object.entries({ EVE_RUNTIME: original.runtime, EVE_SCRIPT_K8S_RUNNER: original.enabled })) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
  calls.length = 0;
});

describe('script runner dispatch egress', () => {
  it('writes the project runner egress policies before the runner pod starts', async () => {
    process.env.EVE_RUNTIME = 'k8s';
    process.env.EVE_SCRIPT_K8S_RUNNER = 'true';
    delete process.env.EVE_RUNNER_SELF_TERMINATE;
    const service = new ScriptExecutorService(null as never);
    (service as unknown as { jobs: unknown }).jobs = {
      findById: vi.fn().mockResolvedValue({ project_id: 'proj_shop', execution_type: 'script', script_command: 'echo test', hints: {} }),
      updateRuntimeMeta: vi.fn(),
    };

    await service.execute('job_1', 'att_1');
    expect(calls).toEqual(['egress:proj_shop', 'runner']);
  });
});
