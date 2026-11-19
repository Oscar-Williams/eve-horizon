import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RUNNER_INBOUND_KEY_HEADER, runnerInboundKeyMatches } from '@eve/shared';
import { dispatchToRunnerPod } from './runner-dispatch.js';

/**
 * The worker authenticates its submit to a runner pod with a key made for
 * that pod: the pod's spec holds only the key's SHA-256, and the submit
 * presents the key. The worker's internal key never reaches the pod, neither
 * in its spec nor on the submit.
 */
const state = vi.hoisted(() => ({ applied: '', phase: 'Running' }));
vi.mock('child_process', async (importOriginal) => ({ ...(await importOriginal<typeof import('node:child_process')>()), spawn: vi.fn((_command: string, args: string[]) => {
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  if (args.includes('apply')) child.stdin.on('data', (chunk: Buffer) => { state.applied += chunk.toString('utf8'); });
  queueMicrotask(() => {
    if (args.includes('get') && args.includes('json')) {
      child.stdout.write(JSON.stringify({ status: { phase: state.phase, podIP: '10.0.0.1', conditions: [{ type: 'Ready', status: 'True' }] } }));
    }
    child.stdout.end(); child.stderr.end(); child.emit('close', 0);
  });
  return child;
}) }));

const submit = { kind: 'agent' as const, job_id: 'job_test', attempt_id: 'attempt_test', project_id: 'proj_test', job_token: 'job-token', api_url: 'http://api.test' };

function appliedPod() {
  const manifest = JSON.parse(state.applied);
  return (manifest.items ?? [manifest]).find((item: { kind: string }) => item.kind === 'Pod');
}

beforeEach(() => {
  state.applied = ''; state.phase = 'Running';
  vi.stubEnv('EVE_RUNNER_IMAGE', 'worker:test');
  vi.stubEnv('EVE_K8S_RUNNER_POLL_MS', '1');
  vi.stubEnv('EVE_INTERNAL_API_KEY', 'platform-internal-key');
  vi.stubEnv('EVE_INTERNAL_CORE_KEY', 'platform-core-key');
});
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

describe('runner pod inbound key', () => {
  it('submits with the key whose hash only the pod holds, and never the internal key', async () => {
    const seen: Array<Record<string, string>> = [];
    vi.stubGlobal('fetch', vi.fn(async (url: string, init?: { headers?: Record<string, string> }) => {
      if (url === 'http://10.0.0.1:4749/health') return new Response('{}', { status: 200 });
      if (url === 'http://10.0.0.1:4749/runner/submit') {
        seen.push(init?.headers ?? {});
        state.phase = 'Succeeded';
        return new Response(JSON.stringify({ accepted: true }), { status: 202 });
      }
      throw new Error(`unexpected fetch ${url}`);
    }));
    let reads = 0;
    const outcome = await dispatchToRunnerPod(submit, { pod: {}, readResult: async () => (++reads > 1 ? { success: true, exit_code: 0 } : null) });

    expect(outcome.success).toBe(true);
    const pod = appliedPod();
    const env = Object.fromEntries(pod.spec.containers[0].env.map((e: { name: string; value: string }) => [e.name, e.value]));
    expect(state.applied).not.toContain('platform-internal-key');
    expect(state.applied).not.toContain('platform-core-key');
    expect(seen).toHaveLength(1);
    const presented = seen[0][RUNNER_INBOUND_KEY_HEADER];
    expect(runnerInboundKeyMatches(presented, env.EVE_RUNNER_INBOUND_KEY_SHA256)).toBe(true);
    expect(state.applied).not.toContain(presented);
    expect(JSON.stringify(seen[0])).not.toContain('platform-');
    expect(pod.spec.automountServiceAccountToken).toBe(false);
  });
});
