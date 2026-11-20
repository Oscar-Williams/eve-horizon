import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { SandboxClaimUnavailable, createSandboxClaimBackend } from './sandbox-claim-backend.js';

/**
 * A claimed pod's liveness. The claim reports its sandbox's name and pod IPs;
 * the pod itself is found by the attempt label the claim puts on it, at the
 * claim's IP, so a pod named apart from its sandbox (agent-sandbox records
 * that in the Sandbox's agents.x-k8s.io/pod-name annotation) is never taken
 * for ended while it runs.
 */
const k = vi.hoisted(() => ({
  podName: 'eve-runner-chat-x1-p9',
  phase: 'Running',
  labelled: true,
  listsBeforeLabel: 0,
  lists: 0,
  calls: [] as string[][],
}));

vi.mock('child_process', async (importOriginal) => ({ ...(await importOriginal<typeof import('node:child_process')>()), spawn: vi.fn((_c: string, args: string[]) => {
  k.calls.push(args);
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  child.stdin.on('data', () => undefined);
  child.stdin.on('finish', () => {
    let code = 0;
    let out = '';
    let err = '';
    const at = (word: string) => args[args.indexOf(word) + 1];
    const pod = { metadata: { name: k.podName, labels: { 'eve.horizon/attempt-id': 'att-1' } }, status: { phase: k.phase, podIP: '10.1.0.7', podIPs: [{ ip: '10.1.0.7' }] } };
    if (args.includes('sandboxclaim')) {
      out = JSON.stringify({ status: { conditions: [{ type: 'Ready', status: 'True' }], sandbox: { name: 'eve-runner-chat-x1', podIPs: ['10.1.0.7'] } } });
    } else if (args.includes('sandbox')) {
      out = JSON.stringify({ metadata: { name: 'eve-runner-chat-x1', annotations: { 'agents.x-k8s.io/pod-name': k.podName } } });
    } else if (args.includes('pods') && args.includes('-l')) {
      k.lists += 1;
      const labelled = k.labelled && k.lists > k.listsBeforeLabel;
      out = JSON.stringify({ items: labelled && at('-l') === 'eve.horizon/attempt-id=att-1' ? [pod] : [] });
    } else if (args.includes('pod')) {
      if (at('pod') === k.podName) out = JSON.stringify(pod);
      else { code = 1; err = `Error from server (NotFound): pods "${at('pod')}" not found`; }
    }
    queueMicrotask(() => {
      child.stdout.write(out);
      child.stderr.write(err);
      child.stdout.end(); child.stderr.end(); child.emit('close', code);
    });
  });
  return child;
}) }));

beforeEach(() => {
  k.podName = 'eve-runner-chat-x1-p9'; k.phase = 'Running'; k.labelled = true; k.listsBeforeLabel = 0; k.lists = 0; k.calls = [];
  vi.stubEnv('EVE_SANDBOX_CLAIM_TIMEOUT', '50ms');
  vi.stubEnv('EVE_SANDBOX_CLAIM_POLL_MS', '5');
});
afterEach(() => vi.unstubAllEnvs());

const backend = () => createSandboxClaimBackend({
  namespace: 'eve-runners',
  jobClass: 'chat',
  submit: { job_id: 'shop-1', attempt_id: 'att-1', project_id: 'proj_shop' },
  timeoutSeconds: 1200,
});

describe('a claimed runner pod', () => {
  it('is the pod the claim labelled at its IP, not one named after the sandbox', async () => {
    const claim = backend();
    const pod = await claim.start();
    expect(pod).toEqual({ ip: '10.1.0.7', podName: 'eve-runner-chat-x1-p9', namespace: 'eve-runners' });
    expect(await claim.podEnded()).toBe(false);
    k.phase = 'Succeeded';
    expect(await claim.podEnded()).toBe(true);
  });

  it('is still found when it shares its sandbox name', async () => {
    k.podName = 'eve-runner-chat-x1';
    const claim = backend();
    expect((await claim.start()).podName).toBe('eve-runner-chat-x1');
    expect(await claim.podEnded()).toBe(false);
  });

  it('waits for the claim to label the pod before it is used', async () => {
    k.listsBeforeLabel = 2;
    const claim = backend();
    expect((await claim.start()).podName).toBe('eve-runner-chat-x1-p9');
    expect(k.lists).toBeGreaterThan(2);
  });

  it('is unavailable (the dispatcher falls back) when no pod carries the label in time', async () => {
    k.labelled = false;
    await expect(backend().start()).rejects.toBeInstanceOf(SandboxClaimUnavailable);
  });
});
