import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { RunnerTemplatesService } from './runner-templates.service.js';

/**
 * The worker renders the runner SandboxTemplates and SandboxWarmPools from
 * its own runner image and the instance settings, at startup and on
 * `eve system security reconcile`. Without the agent-sandbox CRDs it does
 * nothing (runner pods are then created directly).
 */
const k = vi.hoisted(() => ({ crds: true, applied: [] as Array<Record<string, any>>, calls: [] as string[][] }));
vi.mock('child_process', async (importOriginal) => ({ ...(await importOriginal<typeof import('node:child_process')>()), spawn: vi.fn((_c: string, args: string[]) => {
  k.calls.push(args);
  const child = Object.assign(new EventEmitter(), { stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough() });
  let input = '';
  child.stdin.on('data', (chunk: Buffer) => { input += chunk.toString('utf8'); });
  child.stdin.on('finish', () => {
    let out = '';
    if (args.includes('api-resources')) out = k.crds ? 'sandboxclaims.extensions.agents.x-k8s.io\nsandboxtemplates.extensions.agents.x-k8s.io\nsandboxwarmpools.extensions.agents.x-k8s.io\n' : '';
    if (args.includes('apply')) {
      const parsed = JSON.parse(input);
      k.applied.push(...(parsed.items ?? [parsed]));
    }
    queueMicrotask(() => { child.stdout.write(out); child.stdout.end(); child.stderr.end(); child.emit('close', 0); });
  });
  return child;
}) }));

const SETTINGS: Record<string, string> = {
  'runner.runtime_class': 'gvisor',
  'runner.warm_pool.chat': '3',
  'runner.warm_pool.job': '1',
};

function service() {
  const db = Object.assign(vi.fn(async (strings: TemplateStringsArray, ...values: unknown[]) => {
    const sql = strings.join('?');
    if (sql.includes('system_settings')) {
      return Object.entries(SETTINGS).filter(([key]) => JSON.stringify(values).includes(key) || sql.includes(key))
        .map(([key, value]) => ({ key, value }));
    }
    return [];
  }), { json: (v: unknown) => v });
  return new RunnerTemplatesService(db as never);
}

beforeEach(() => {
  k.crds = true; k.applied = []; k.calls = [];
  vi.stubEnv('EVE_RUNNER_IMAGE', 'eve-horizon/worker:0.1.327');
  vi.stubEnv('EVE_RUNNER_NAMESPACE', 'eve-runners');
  vi.stubEnv('EVE_INTERNAL_CORE_KEY', 'core-key-for-test');
  vi.stubEnv('EVE_INTERNAL_API_KEY', '');
  vi.stubEnv('EVE_RUNNER_POOL_KEY', '');
});
afterEach(() => vi.unstubAllEnvs());

describe('runner template reconcile', () => {
  it('applies a template and a warm pool per class from the runner image and the instance settings', async () => {
    const report = await service().reconcile();
    expect(report).toMatchObject({ backend: 'sandbox', namespace: 'eve-runners' });
    const names = k.applied.map((o) => `${o.kind}/${o.metadata.name}`).sort();
    expect(names).toEqual([
      'SandboxTemplate/eve-runner-chat', 'SandboxTemplate/eve-runner-heavy', 'SandboxTemplate/eve-runner-job',
      'SandboxWarmPool/eve-runner-chat', 'SandboxWarmPool/eve-runner-heavy', 'SandboxWarmPool/eve-runner-job',
    ]);
    const chat = k.applied.find((o) => o.kind === 'SandboxTemplate' && o.metadata.name === 'eve-runner-chat')!;
    expect(chat.spec.podTemplate.spec.containers[0].image).toBe('eve-horizon/worker:0.1.327');
    expect(chat.spec.podTemplate.spec.runtimeClassName).toBe('gvisor');
    expect(k.applied.find((o) => o.kind === 'SandboxWarmPool' && o.metadata.name === 'eve-runner-chat')!.spec.replicas).toBe(3);
  });

  it("sizes the heavy class's workspace claim from EVE_K8S_WORKSPACE_SIZE", async () => {
    vi.stubEnv('EVE_K8S_WORKSPACE_SIZE', '5Gi');
    await service().reconcile();
    const heavy = k.applied.find((o) => o.kind === 'SandboxTemplate' && o.metadata.name === 'eve-runner-heavy')!;
    expect(heavy.spec.volumeClaimTemplates[0].spec.resources.requests.storage).toBe('5Gi');
  });

  it("puts only the hash of the worker's pool key in every template, which changes when the key does", async () => {
    const poolHash = (objects: Array<Record<string, any>>) => objects.filter((o) => o.kind === 'SandboxTemplate')
      .map((o) => o.spec.podTemplate.spec.containers[0].env.find((e: { name: string }) => e.name === 'EVE_RUNNER_POOL_KEY_SHA256')?.value);

    await service().reconcile();
    const derived = poolHash(k.applied);
    expect(derived).toHaveLength(3);
    expect(new Set(derived).size).toBe(1);
    expect(derived[0]).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(k.applied)).not.toContain('core-key-for-test');

    k.applied = [];
    vi.stubEnv('EVE_RUNNER_POOL_KEY', 'pool-key-for-test');
    await service().reconcile();
    const dedicated = poolHash(k.applied);
    expect(dedicated[0]).toBe(createHash('sha256').update('pool-key-for-test').digest('hex'));
    expect(JSON.stringify(k.applied)).not.toContain('pool-key-for-test');
    expect(dedicated[0]).not.toBe(derived[0]);
  });

  it('renders no template when the worker holds no key to derive the pool key from', async () => {
    vi.stubEnv('EVE_INTERNAL_CORE_KEY', '');
    const report = await service().reconcile();
    expect(report).toMatchObject({ backend: 'pod' });
    expect(report.reason).toMatch(/pool key/);
    expect(k.applied).toEqual([]);
  });

  it('does nothing without the agent-sandbox CRDs', async () => {
    k.crds = false;
    const report = await service().reconcile();
    expect(report).toMatchObject({ backend: 'pod' });
    expect(k.applied).toEqual([]);
  });
});
