import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { dispatchToRunnerPod } from './runner-dispatch.js';
import { resetSandboxDiscovery } from './sandbox-claim-backend.js';

/**
 * Where a runner pod comes from. With the agent-sandbox CRDs present (and the
 * class's warm pool rendered), the worker claims one through a SandboxClaim
 * in the runner namespace and reaches it at status.sandbox.podIPs; a claim
 * not Ready within EVE_SANDBOX_CLAIM_TIMEOUT, or failed, is deleted and the
 * identical pod is created directly. Without the CRDs the pod is created
 * directly. A job that mounts the org filesystem runs as a plain pod in the
 * platform namespace, where the org filesystem claim lives.
 */
const k = vi.hoisted(() => ({
  crds: true,
  pool: true,
  poolReplicas: 3,
  runnerNamespace: true,
  claim: 'ready' as 'ready' | 'pending' | 'failed',
  podPhase: 'Running',
  applied: [] as Array<Record<string, any>>,
  calls: [] as string[][],
}));

vi.mock('child_process', async (importOriginal) => ({ ...(await importOriginal<typeof import('node:child_process')>()), spawn: vi.fn((_c: string, args: string[]) => {
  k.calls.push(args);
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  let input = '';
  child.stdin.on('data', (chunk: Buffer) => { input += chunk.toString('utf8'); });
  child.stdin.on('finish', () => {
    let code = 0;
    let out = '';
    let err = '';
    const has = (...words: string[]) => words.every((w) => args.includes(w));
    const noRunnerNamespace = 'Error from server (NotFound): namespaces "eve-runners" not found';
    if (has('get', 'namespace')) {
      code = k.runnerNamespace ? 0 : 1;
      if (k.runnerNamespace) out = 'namespace/eve-runners'; else err = noRunnerNamespace;
    } else if (has('apply') && !k.runnerNamespace && input.includes('"namespace":"eve-runners"')) {
      code = 1;
      err = noRunnerNamespace;
    } else if (args.includes('api-resources')) {
      out = k.crds ? 'sandboxclaims.extensions.agents.x-k8s.io\nsandboxtemplates.extensions.agents.x-k8s.io\nsandboxwarmpools.extensions.agents.x-k8s.io\n' : '';
    } else if (has('apply')) {
      const parsed = JSON.parse(input);
      k.applied.push(...(parsed.items ?? [parsed]));
    } else if (has('get', 'sandboxwarmpool')) {
      code = k.pool ? 0 : 1;
      out = k.pool ? JSON.stringify({ metadata: { name: args[args.indexOf('sandboxwarmpool') + 1] }, spec: { replicas: k.poolReplicas } }) : '';
    } else if (has('get', 'sandboxclaim')) {
      out = JSON.stringify(k.claim === 'ready'
        ? { status: { conditions: [{ type: 'Ready', status: 'True' }], sandbox: { name: 'eve-runner-chat-x1', podIPs: ['10.1.0.7'] } } }
        : k.claim === 'failed'
          ? { status: { conditions: [{ type: 'Ready', status: 'False', reason: 'InvalidMetadata' }] } }
          : { status: {} });
    } else if (has('get', 'pods', '-l')) {
      // The claimed pod, found by the attempt label the claim puts on it.
      out = JSON.stringify({ items: [{ metadata: { name: 'eve-runner-chat-x1' }, status: { phase: k.podPhase, podIP: '10.1.0.7' } }] });
    } else if (has('get', 'pod')) {
      out = JSON.stringify({ status: { phase: k.podPhase, podIP: '10.2.0.9', conditions: [{ type: 'Ready', status: 'True' }] } });
    }
    queueMicrotask(() => {
      child.stdout.write(out);
      child.stderr.write(err);
      child.stdout.end(); child.stderr.end(); child.emit('close', code);
    });
  });
  return child;
}) }));

// egress.default_deny: the project's runner policies come before any claim or pod.
vi.mock('../network/runner-egress.js', () => ({
  ensureRunnerEgress: vi.fn(async (projectId: string) => { k.calls.push(['ensure-runner-egress', projectId]); }),
}));

const submit = { kind: 'agent' as const, job_id: 'shop-1', attempt_id: 'att-1', project_id: 'proj_shop', job_token: 't', api_url: 'http://api.test' };
let submittedTo: string[] = [];

beforeEach(() => {
  k.crds = true; k.pool = true; k.poolReplicas = 3; k.runnerNamespace = true; k.claim = 'ready'; k.podPhase = 'Running'; k.applied = []; k.calls = [];
  submittedTo = [];
  resetSandboxDiscovery();
  vi.stubEnv('EVE_RUNNER_IMAGE', 'worker:test');
  vi.stubEnv('EVE_RUNNER_NAMESPACE', 'eve-runners');
  vi.stubEnv('EVE_K8S_NAMESPACE', 'eve');
  vi.stubEnv('EVE_K8S_RUNNER_POLL_MS', '1');
  vi.stubEnv('EVE_SANDBOX_CLAIM_TIMEOUT', '30ms');
  vi.stubEnv('EVE_SANDBOX_CLAIM_POLL_MS', '5');
  vi.stubGlobal('fetch', vi.fn(async (url: string) => {
    if (url.endsWith('/health')) return new Response('{}', { status: 200 });
    if (url.endsWith('/runner/submit')) {
      submittedTo.push(url);
      k.podPhase = 'Succeeded';
      return new Response('{"accepted":true}', { status: 202 });
    }
    throw new Error(`unexpected fetch ${url}`);
  }));
});
afterEach(() => { vi.unstubAllEnvs(); vi.unstubAllGlobals(); });

function run(pod: Record<string, unknown> = {}) {
  let reads = 0;
  return dispatchToRunnerPod(submit, {
    pod: { jobClass: 'chat', timeoutSeconds: 1200, runtimeClass: 'gvisor', ...pod },
    readResult: async () => (submittedTo.length > 0 && ++reads > 0 ? { success: true, exit_code: 0 } : null),
  });
}

const claimsApplied = () => k.applied.filter((o) => o.kind === 'SandboxClaim');
const podsApplied = () => k.applied.filter((o) => o.kind === 'Pod');
const deleted = (kind: string) => k.calls.filter((a) => a[0] === '--request-timeout=10s' ? a[1] === 'delete' && a[2] === kind : a[0] === 'delete' && a[1] === kind);

describe('runner pod backends', () => {
  it('claims a sandbox when the CRDs are present, reaches it at its pod IP, and deletes the claim', async () => {
    const outcome = await run();
    expect(outcome.success).toBe(true);
    expect(claimsApplied()).toEqual([expect.objectContaining({
      metadata: expect.objectContaining({ namespace: 'eve-runners' }),
      spec: expect.objectContaining({ warmPoolRef: { name: 'eve-runner-chat' } }),
    })]);
    expect(podsApplied()).toEqual([]);
    expect(submittedTo).toEqual(['http://10.1.0.7:4749/runner/submit']);
    expect(deleted('sandboxclaim')).toHaveLength(1);
  });

  it('deletes a claim that is not Ready in time and creates the identical pod directly', async () => {
    k.claim = 'pending';
    const outcome = await run();
    expect(outcome.success).toBe(true);
    expect(deleted('sandboxclaim').length).toBeGreaterThanOrEqual(1);
    const [pod] = podsApplied();
    expect(pod.metadata.namespace).toBe('eve-runners');
    expect(pod.metadata.labels).toMatchObject({ 'eve.horizon/project-id': 'proj_shop', 'eve.horizon/attempt-id': 'att-1', 'eve.horizon/job-class': 'chat', 'eve.horizon/runner': 'true' });
    expect(pod.spec.runtimeClassName).toBe('gvisor');
    expect(pod.spec.nodeSelector).toMatchObject({ 'sandbox.gke.io/runtime': 'gvisor' });
    expect(pod.spec.volumes).toContainEqual(expect.objectContaining({ name: 'workspace', emptyDir: expect.any(Object) }));
    expect(submittedTo).toEqual(['http://10.2.0.9:4749/runner/submit']);
  });

  it('deletes a failed claim at once and falls back', async () => {
    k.claim = 'failed';
    const outcome = await run();
    expect(outcome.success).toBe(true);
    expect(deleted('sandboxclaim').length).toBeGreaterThanOrEqual(1);
    expect(podsApplied()).toHaveLength(1);
  });

  it("creates the pod directly when the class's warm pool is sized 0, rather than wait on a cold claim", async () => {
    k.poolReplicas = 0;
    const outcome = await run();
    expect(outcome.success).toBe(true);
    expect(claimsApplied()).toEqual([]);
    expect(podsApplied()).toHaveLength(1);
  });

  it('fails with the missing runner namespace and the install step it needs', async () => {
    for (const crds of [true, false]) {
      k.runnerNamespace = false; k.crds = crds; k.pool = false; k.applied = [];
      resetSandboxDiscovery();
      const outcome = await run();
      expect(outcome.success).toBe(false);
      expect(outcome.error).toMatch(/runner namespace eve-runners does not exist/i);
      expect(outcome.error).toMatch(/runner-namespace\.yaml/);
      expect(podsApplied()).toEqual([]);
    }
  });

  it('creates the pod directly without the CRDs', async () => {
    k.crds = false;
    const outcome = await run();
    expect(outcome.success).toBe(true);
    expect(claimsApplied()).toEqual([]);
    expect(podsApplied()[0].metadata.namespace).toBe('eve-runners');
  });

  it('runs a job that mounts the org filesystem as a plain pod in the platform namespace', async () => {
    const outcome = await run({ orgFs: { readOnly: true } });
    expect(outcome.success).toBe(true);
    expect(claimsApplied()).toEqual([]);
    const [pod] = podsApplied();
    expect(pod.metadata.namespace).toBe('eve');
    expect(pod.spec.containers[0].volumeMounts).toContainEqual({ name: 'org-fs', mountPath: '/org', readOnly: true });
  });

  it('brings the project runner egress policies in line before it claims or creates a pod, on every path', async () => {
    const firstWrite = () => k.calls.findIndex((args) => args.includes('apply'));
    for (const setup of [() => {}, () => { k.claim = 'pending'; }, () => { k.crds = false; }]) {
      k.crds = true; k.claim = 'ready'; k.podPhase = 'Running'; k.applied = []; k.calls = []; submittedTo = [];
      resetSandboxDiscovery();
      setup();
      expect((await run()).success).toBe(true);
      expect(k.calls[0]).toEqual(['ensure-runner-egress', 'proj_shop']);
      expect(firstWrite()).toBeGreaterThan(0);
    }
    k.applied = []; k.calls = []; submittedTo = []; k.podPhase = 'Running';
    expect((await run({ orgFs: { readOnly: true } })).success).toBe(true);
    expect(k.calls[0]).toEqual(['ensure-runner-egress', 'proj_shop']);
  });
});
