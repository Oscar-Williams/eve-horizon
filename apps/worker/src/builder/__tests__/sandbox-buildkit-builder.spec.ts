import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
vi.mock('../../invoke/k8s-runner.js', async (original) => ({ ...await original<any>(), execKubectl: vi.fn() }));
import { execKubectl } from '../../invoke/k8s-runner.js';
import { ROOTLESS_BUILDKIT_IMAGE, SandboxBuildKitBuilder } from '../sandbox-buildkit-builder.js';
import type { BuildServiceParams } from '../image-builder.interface.js';

const params: BuildServiceParams = {
  projectId: 'proj_shop', serviceName: 'web', service: { build: { context: '.' } },
  registryConfig: { host: 'registry.example.com' },
  registryAuth: { host: 'registry.example.com', username: 'client-only-user', token: 'client-only-token', dockerConfigJson: 'client-only-config' },
  gitSha: 'abc', workspacePath: '/workspace', tag: 'sha-abc', imageRef: 'registry.example.com/web',
};
let claim: any;
let pod: any;
let pool: any;
let ready: boolean;
let client: any;
let createError: boolean;
let deleteError: boolean;
const kubectl = vi.mocked(execKubectl);

beforeEach(() => {
  vi.useRealTimers();
  vi.unstubAllEnvs();
  claim = undefined; ready = true; createError = false; deleteError = false;
  pool = { spec: { replicas: 0, sandboxTemplateRef: { name: 'eve-builder' } } };
  pod = {
    metadata: { name: 'builder-pod', ownerReferences: [{ kind: 'Sandbox', name: 'bound-sandbox', controller: true }] },
    spec: { runtimeClassName: 'gvisor', automountServiceAccountToken: false,
      securityContext: { runAsUser: 1000, runAsGroup: 1000, runAsNonRoot: true },
      containers: [{ name: 'buildkit', image: ROOTLESS_BUILDKIT_IMAGE }], volumes: [{ name: 'state', emptyDir: {} }] },
    status: { phase: 'Running', podIP: '10.10.0.2', conditions: [{ type: 'Ready', status: 'True' }] },
  };
  client = { buildServiceAt: vi.fn().mockResolvedValue('sha256:result') };
  kubectl.mockReset().mockImplementation(async (args, input) => {
    if (args[0] === 'create') {
      claim = JSON.parse(input!);
      pod.metadata.labels = claim.spec.additionalPodMetadata.labels;
      if (createError) return { stdout: '', stderr: 'connection lost', exitCode: 1 };
      return { stdout: '{}', stderr: '', exitCode: 0 };
    }
    if (args[0] === 'delete') return { stdout: '', stderr: deleteError ? 'delete denied' : '', exitCode: deleteError ? 1 : 0 };
    const value = args[1].startsWith('sandboxwarmpools') ? pool : args[1] === 'pods' ? { items: [pod] } : {
      status: { conditions: [{ type: 'Ready', status: ready ? 'True' : 'False' }], sandbox: { name: 'bound-sandbox', podIPs: ['10.10.0.2'] } },
    };
    return { stdout: JSON.stringify(value), stderr: '', exitCode: 0 };
  });
});
afterEach(() => { vi.useRealTimers(); vi.unstubAllEnvs(); });
const run = (extra = {}) => new SandboxBuildKitBuilder(client).buildService({ ...params, ...extra });
const deletions = () => kubectl.mock.calls.filter(([args]) => args[0] === 'delete');

describe('per-build rootless BuildKit', () => {
  it('uses a distinct labelled claim, only its verified endpoint, and deletes it after the client finishes', async () => {
    vi.stubEnv('EVE_BUILDKIT_ADDR', 'tcp://shared:1234');
    vi.stubEnv('BUILDKIT_HOST', 'tcp://another-shared:1234');
    await expect(run()).resolves.toBe('sha256:result');
    const firstName = claim.metadata.name;
    expect(claim.spec).toMatchObject({ warmPoolRef: { name: 'eve-builder' }, additionalPodMetadata: { labels: { 'eve.horizon/project-id': 'proj_shop' } }, lifecycle: { shutdownPolicy: 'Delete' } });
    expect(Date.parse(claim.spec.lifecycle.shutdownTime)).toBeGreaterThan(Date.now());
    expect(client.buildServiceAt).toHaveBeenCalledWith(expect.objectContaining({ projectId: params.projectId, registryAuth: params.registryAuth, signal: expect.any(AbortSignal) }), 'tcp://10.10.0.2:1234', true);
    expect(deletions()).toHaveLength(1);
    expect(deletions()[0][0]).toContain('--cascade=foreground');
    expect(client.buildServiceAt.mock.invocationCallOrder[0]).toBeLessThan(kubectl.mock.invocationCallOrder.at(-1)!);
    await run();
    expect(claim.metadata.name).not.toBe(firstName);
    const requests = JSON.stringify(kubectl.mock.calls);
    for (const sensitive of ['client-only-user', 'client-only-token', 'client-only-config', 'Secret', '/workspace']) expect(requests).not.toContain(sensitive);
  });

  it('deletes after build failure and never retries another backend', async () => {
    client.buildServiceAt.mockRejectedValue(new Error('build failed'));
    await expect(run()).rejects.toThrow('build failed');
    expect(deletions()).toHaveLength(1);
    expect(client.buildServiceAt).toHaveBeenCalledOnce();
  });

  it('cleans up an uncertain create outcome', async () => {
    createError = true;
    await expect(run()).rejects.toThrow('connection lost');
    expect(deletions()).toHaveLength(1);
    expect(client.buildServiceAt).not.toHaveBeenCalled();
  });

  it('reports cleanup failure even after a successful push', async () => {
    deleteError = true;
    await expect(run()).rejects.toThrow('builder_cleanup_failed');
  });

  it('preserves build and cleanup failures together', async () => {
    client.buildServiceAt.mockRejectedValue(new Error('build failed')); deleteError = true;
    await expect(run()).rejects.toThrow(/build failed; builder_cleanup_failed/);
  });

  it('refuses a warm builder pool before claiming', async () => {
    pool.spec.replicas = 1;
    await expect(run()).rejects.toThrow('replicas=0');
    expect(claim).toBeUndefined(); expect(client.buildServiceAt).not.toHaveBeenCalled();
  });

  it('does no Kubernetes or credential work for an already cancelled build', async () => {
    const cancellation = new AbortController(); cancellation.abort(new Error('job cancelled'));
    await expect(run({ signal: cancellation.signal })).rejects.toThrow('job cancelled');
    expect(kubectl).not.toHaveBeenCalled();
  });

  it('cancels an active build and cleans up with an independent signal', async () => {
    const cancellation = new AbortController();
    client.buildServiceAt.mockImplementation(async ({ signal }: BuildServiceParams) => {
      cancellation.abort(new Error('job cancelled'));
      signal!.throwIfAborted();
    });
    await expect(run({ signal: cancellation.signal })).rejects.toThrow('job cancelled');
    expect(deletions()).toHaveLength(1);
    expect(deletions()[0][2]!.aborted).toBe(false);
  });

  it('cleans up when readiness times out', async () => {
    vi.useFakeTimers(); vi.stubEnv('EVE_BUILD_READY_TIMEOUT', '1s'); ready = false;
    const outcome = expect(run()).rejects.toThrow('not Ready');
    await vi.advanceTimersByTimeAsync(1_001); await outcome;
    expect(deletions()).toHaveLength(1); expect(client.buildServiceAt).not.toHaveBeenCalled();
  });

  it('enforces the total deadline during the build session', async () => {
    vi.useFakeTimers(); vi.stubEnv('EVE_BUILD_TIMEOUT', '1s');
    client.buildServiceAt.mockImplementation(({ signal }: BuildServiceParams) => new Promise((_, reject) => {
      signal!.addEventListener('abort', () => reject(signal!.reason), { once: true });
    }));
    const outcome = expect(run()).rejects.toThrow('build_timeout');
    await vi.advanceTimersByTimeAsync(1_001); await outcome;
    expect(deletions()).toHaveLength(1); expect(deletions()[0][2]!.aborted).toBe(false);
  });

  it.each([
    ['root user', () => { pod.spec.containers[0].securityContext = { runAsUser: 0 }; }],
    ['different image', () => { pod.spec.containers[0].image = 'moby/buildkit:latest'; }],
    ['different runtime', () => { pod.spec.runtimeClassName = 'runc'; }],
    ['host network', () => { pod.spec.hostNetwork = true; }],
    ['service account', () => { pod.spec.automountServiceAccountToken = true; }],
    ['secret volume', () => { pod.spec.volumes.push({ name: 'auth', secret: { secretName: 'credentials' } }); }],
    ['secret env', () => { pod.spec.containers[0].env = [{ name: 'AUTH', valueFrom: {} }]; }],
    ['sidecar', () => { pod.spec.containers.push({ name: 'sidecar' }); }],
    ['different owner', () => { pod.metadata.ownerReferences[0].name = 'another-sandbox'; }],
  ])('refuses %s before opening a credential session', async (_, mutate) => {
    mutate();
    await expect(run()).rejects.toThrow('does not match');
    expect(client.buildServiceAt).not.toHaveBeenCalled(); expect(deletions()).toHaveLength(1);
  });
});
