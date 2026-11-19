import { describe, expect, it, vi } from 'vitest';
import { runInRunnerPod, type RunnerPodBackend } from './runner-dispatch.js';

/**
 * The worker records a runner attempt only once the runner's pushed result
 * exists and its pod has ended. A pod that ends with no result fails the
 * attempt. The pod is removed whatever happens.
 */
const submit = {
  kind: 'agent' as const,
  job_id: 'shop-1',
  attempt_id: 'att-a',
  project_id: 'proj_shop',
  job_token: 'job-token-a',
  api_url: 'http://eve-api.test',
};
const RESULT = { success: true, exit_code: 0, result_text: 'done', token_input: 3, token_output: 5 };

function backend(endedAfter: number | null, events: string[]): RunnerPodBackend & { calls: { ended: number } } {
  const calls = { ended: 0 };
  return {
    calls,
    start: vi.fn(async () => { events.push('start'); return { ip: '10.0.0.5', podName: 'eve-runner-att-a', namespace: 'eve-runners' }; }),
    podEnded: vi.fn(async () => {
      calls.ended += 1;
      const ended = endedAfter !== null && calls.ended >= endedAfter;
      events.push(`ended:${ended}`);
      return ended;
    }),
    stop: vi.fn(async () => { events.push('stop'); }),
  };
}

function deps(b: RunnerPodBackend, results: Array<typeof RESULT | null>, events: string[]) {
  let reads = 0;
  return {
    backend: b,
    submit: vi.fn(async () => { events.push('submit'); }),
    readResult: vi.fn(async () => {
      const value = results[Math.min(reads, results.length - 1)];
      reads += 1;
      events.push(`result:${value ? 'yes' : 'no'}`);
      return value;
    }),
    sleep: vi.fn(async () => undefined),
  };
}

describe('runner dispatch', () => {
  it('returns the result only after the pod has ended', async () => {
    const events: string[] = [];
    const b = backend(4, events);
    const d = deps(b, [null, RESULT], events);

    const outcome = await runInRunnerPod(submit, d, { inboundKey: 'k', pollMs: 1, resultGraceMs: 1000 });

    expect(outcome).toMatchObject({ attemptId: 'att-a', success: true, exitCode: 0, resultText: 'done', tokenInput: 3, tokenOutput: 5 });
    const firstResult = events.indexOf('result:yes');
    const podEnd = events.indexOf('ended:true');
    expect(firstResult).toBeGreaterThan(-1);
    expect(podEnd).toBeGreaterThan(firstResult);
    expect(events.at(-1)).toBe('stop');
    expect(d.submit).toHaveBeenCalledWith('10.0.0.5', submit, 'k', undefined);
  });

  it('fails the attempt when the pod ends with no result', async () => {
    const events: string[] = [];
    const b = backend(2, events);
    const d = deps(b, [null], events);

    const outcome = await runInRunnerPod(submit, d, { inboundKey: 'k', pollMs: 1 });

    expect(outcome).toMatchObject({ attemptId: 'att-a', success: false });
    expect(outcome.error).toMatch(/ended without a result/);
    expect(b.stop).toHaveBeenCalled();
  });

  it('removes a pod that outlives its result, then returns once it has gone', async () => {
    const events: string[] = [];
    let stopped = false;
    const b: RunnerPodBackend = {
      start: vi.fn(async () => ({ ip: '10.0.0.5', podName: 'p', namespace: 'eve-runners' })),
      podEnded: vi.fn(async () => { events.push(`ended:${stopped}`); return stopped; }),
      stop: vi.fn(async () => { stopped = true; events.push('stop'); }),
    };
    const d = deps(b, [RESULT], events);
    let clock = 0;

    const outcome = await runInRunnerPod(submit, { ...d, now: () => (clock += 500) }, { inboundKey: 'k', pollMs: 1, resultGraceMs: 2000 });

    expect(outcome.success).toBe(true);
    expect(events.indexOf('stop')).toBeLessThan(events.lastIndexOf('ended:true'));
  });

  it('fails and removes the pod when the submit is refused', async () => {
    const events: string[] = [];
    const b = backend(1, events);
    const d = { ...deps(b, [null], events), submit: vi.fn(async () => { throw new Error('Runner submit failed: 401'); }) };

    const outcome = await runInRunnerPod(submit, d, { inboundKey: 'k', pollMs: 1 });

    expect(outcome).toMatchObject({ success: false });
    expect(outcome.error).toMatch(/401/);
    expect(b.stop).toHaveBeenCalled();
  });
});
