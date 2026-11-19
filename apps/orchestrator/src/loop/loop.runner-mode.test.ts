import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation } from '@eve/shared';

/**
 * isolation.runner_mode at dispatch: an agent job goes to the worker (which
 * runs it in a runner pod) under the project's strict profile or when the
 * instance sets EVE_RUNNER_PODS_ONLY; otherwise to the agent runtime, which
 * runs it inline, and under audit that inline run is recorded.
 */
const m = vi.hoisted(() => ({
  mode: { profile: 'legacy', podsOnly: false, required: false } as { profile: string; podsOnly: boolean; required: boolean },
  findings: [] as Array<Record<string, unknown>>,
}));
vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  runnerModeFor: vi.fn(async () => m.mode),
  recordRunnerModeFinding: vi.fn(async (_db: unknown, finding: Record<string, unknown>) => { m.findings.push(finding); }),
}));

import { agentJobTarget } from './loop.service';

const invocation = {
  jobId: 'shop-1', attemptId: 'att-1', projectId: 'proj_shop', text: 'review',
  toolchains: ['python'], data: { orgfs_mount: { mode: 'read', allow_prefixes: ['/docs'] } },
} as unknown as HarnessInvocation;

beforeEach(() => {
  m.findings = [];
});

describe('agent job dispatch target', () => {
  it("sends a strict project's agent job to the worker", async () => {
    m.mode = { profile: 'strict', podsOnly: false, required: true };
    expect(await agentJobTarget({} as never, invocation, { agentRuntimeConfigured: true })).toBe('worker');
    expect(m.findings).toEqual([]);
  });

  it("sends an audit project's agent job to the agent runtime and records the inline run", async () => {
    m.mode = { profile: 'audit', podsOnly: false, required: false };
    expect(await agentJobTarget({} as never, invocation, { agentRuntimeConfigured: true })).toBe('agent-runtime');
    expect(m.findings).toEqual([expect.objectContaining({
      projectId: 'proj_shop',
      profile: 'audit',
      detail: expect.objectContaining({ kind: 'agent', job_id: 'shop-1', orgfs_mount: 'read', toolchains: 'python', strict_blocker: 'orgfs_mount' }),
    })]);
  });

  it('sends every agent job to the worker when the instance sets EVE_RUNNER_PODS_ONLY', async () => {
    m.mode = { profile: 'audit', podsOnly: true, required: true };
    expect(await agentJobTarget({} as never, invocation, { agentRuntimeConfigured: true })).toBe('worker');
    m.mode = { profile: 'legacy', podsOnly: true, required: true };
    expect(await agentJobTarget({} as never, invocation, { agentRuntimeConfigured: true })).toBe('worker');
  });

  it('keeps legacy projects on the agent runtime with no finding', async () => {
    m.mode = { profile: 'legacy', podsOnly: false, required: false };
    expect(await agentJobTarget({} as never, invocation, { agentRuntimeConfigured: true })).toBe('agent-runtime');
    expect(m.findings).toEqual([]);
  });

  it('uses the worker when no agent runtime is configured', async () => {
    m.mode = { profile: 'audit', podsOnly: false, required: false };
    expect(await agentJobTarget({} as never, invocation, { agentRuntimeConfigured: false })).toBe('worker');
    expect(m.findings).toEqual([]);
  });
});
