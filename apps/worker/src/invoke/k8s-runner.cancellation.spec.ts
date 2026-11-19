import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { dispatchToRunnerPod } from './runner-dispatch.js';

const state = vi.hoisted(() => ({ calls: [] as string[][], ready: false }));
vi.mock('child_process', async (importOriginal) => ({ ...(await importOriginal<typeof import('node:child_process')>()), spawn: vi.fn((_command: string, args: string[], options: { signal?: AbortSignal }) => {
  state.calls.push(args);
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  queueMicrotask(() => {
    if (options.signal?.aborted) { child.emit('error', options.signal.reason); return; }
    if (args.includes('get') && args.includes('json')) {
      child.stdout.write(JSON.stringify({ status: { phase: 'Running', podIP: '10.0.0.1',
        conditions: [{ type: 'Ready', status: state.ready ? 'True' : 'False' }] } }));
    }
    child.stdout.end(); child.stderr.end(); child.emit('close', 0);
  });
  return child;
}) }));

const submit = { kind: 'agent' as const, job_id: 'job_test', attempt_id: 'attempt_test', project_id: 'proj_test', job_token: 't', api_url: 'http://api.test' };
beforeEach(() => {
  state.calls = []; state.ready = false;
  vi.stubEnv('EVE_RUNNER_IMAGE', 'runtime:test');
  vi.stubEnv('EVE_K8S_RUNNER_POLL_MS', '1');
});
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

function run(controller: AbortController, onCreated?: () => Promise<void>, readResult = async () => null) {
  return dispatchToRunnerPod(submit, { pod: {}, readResult, onPodCreated: onCreated, signal: controller.signal });
}

describe('dedicated runner cancellation', () => {
  it('creates no resources for a job cancelled before dispatch', async () => {
    const controller = new AbortController();
    controller.abort(new Error('job_cancelled'));
    await expect(run(controller)).rejects.toThrow('job_cancelled');
    expect(state.calls).toEqual([]);
  });

  it('deletes a runner cancelled during startup with a bounded grace period', async () => {
    const controller = new AbortController();
    await expect(run(controller, async () => { controller.abort(new Error('job_cancelled')); }))
      .rejects.toThrow('job_cancelled');
    expect(state.calls).toContainEqual(expect.arrayContaining(['delete', 'pod', '--grace-period=5']));
  });

  it('stops waiting for the result and removes the running pod', async () => {
    const controller = new AbortController(); state.ready = true;
    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify({ accepted: true }), { status: 202 })));
    const readResult = vi.fn(async () => { controller.abort(new Error('job_cancelled')); return null; });
    await expect(run(controller, undefined, readResult)).rejects.toThrow('job_cancelled');
    expect(state.calls).toContainEqual(expect.arrayContaining(['delete', 'pod', '--grace-period=5']));
  });
});
