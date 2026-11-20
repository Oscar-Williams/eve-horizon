import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation } from '@eve/shared';

/**
 * Rule isolation.runner_mode in the agent runtime itself. The orchestrator
 * sends a strict project's agent jobs (and every job under the instance
 * switch EVE_RUNNER_PODS_ONLY) to the worker, but the agent runtime does not
 * rely on that: it refuses to run such a job inline, with the same decision
 * the worker uses, and still hands it to the worker in runner mode.
 */
const mocks = vi.hoisted(() => ({
  decision: { profile: 'strict', podsOnly: false, required: true } as { profile: string; podsOnly: boolean; required: boolean },
  runnerModeFor: vi.fn(),
  recordRunnerModeFinding: vi.fn(async () => undefined),
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  runnerModeFor: mocks.runnerModeFor,
  recordRunnerModeFinding: mocks.recordRunnerModeFinding,
}));

import { InvokeService } from './invoke.service.js';

const invocation = { jobId: 'shop-1', attemptId: 'att-1', projectId: 'proj_shop', text: 'go', harness: 'claude',
  workspacePath: '/tmp/eve-runner-mode-test' } as unknown as HarnessInvocation;

function service() {
  const svc = new InvokeService(null as never);
  (svc as any).jobs = { findById: vi.fn(async () => ({ phase: 'active' })), updateRuntimeMeta: vi.fn(async () => ({})), markExecutionStarted: vi.fn() };
  vi.spyOn(svc as any, 'applyManifestDefaults').mockImplementation(async (inv: unknown) => inv);
  const inline = vi.spyOn(svc as any, 'provisionRequestedToolchains').mockResolvedValue({
    ok: false, failure: { attemptId: 'att-1', success: false, exitCode: 1, error: 'stopped by the test' },
  });
  const toWorker = vi.spyOn(svc as any, 'dispatchToRunner').mockResolvedValue({ attemptId: 'att-1', success: true, exitCode: 0 });
  return { svc, inline, toWorker };
}

beforeEach(() => {
  // The inline path's workspace cleanup reads the service config.
  vi.stubEnv('DATABASE_URL', 'postgres://eve.example/test');
  mocks.runnerModeFor.mockReset();
  mocks.runnerModeFor.mockImplementation(async () => mocks.decision);
  mocks.recordRunnerModeFinding.mockClear();
});
afterEach(() => { vi.unstubAllEnvs(); vi.restoreAllMocks(); });

describe('isolation.runner_mode in the agent runtime', () => {
  it("refuses to run a strict project's agent job inline, with a clear error", async () => {
    mocks.decision = { profile: 'strict', podsOnly: false, required: true };
    const { svc, inline } = service();
    const result = await svc.execute(invocation);
    expect(result).toMatchObject({ success: false });
    expect(result.error).toMatch(/isolation\.runner_mode/);
    expect(result.error).toMatch(/runner pod/);
    expect(inline).not.toHaveBeenCalled();
    expect(mocks.runnerModeFor).toHaveBeenCalledWith(null, 'proj_shop');
  });

  it('refuses it under the instance switch whatever the profile', async () => {
    mocks.decision = { profile: 'legacy', podsOnly: true, required: true };
    const { svc, inline } = service();
    expect((await svc.execute(invocation)).error).toMatch(/EVE_RUNNER_PODS_ONLY/);
    expect(inline).not.toHaveBeenCalled();
  });

  it('runs an audit or legacy project inline as before', async () => {
    mocks.decision = { profile: 'audit', podsOnly: false, required: false };
    const { svc, inline } = service();
    expect((await svc.execute(invocation)).error).toBe('stopped by the test');
    expect(inline).toHaveBeenCalled();
  });

  it('still hands a strict job to the worker in runner mode', async () => {
    vi.stubEnv('EVE_RUNTIME', 'k8s');
    vi.stubEnv('EVE_AGENT_RUNTIME_EXECUTION_MODE', 'runner');
    mocks.decision = { profile: 'strict', podsOnly: false, required: true };
    const { svc, toWorker } = service();
    expect((await svc.execute(invocation)).success).toBe(true);
    expect(toWorker).toHaveBeenCalled();
  });
});
