import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation } from '@eve/shared';
import { InvokeService } from './invoke.service.js';

const cleanup: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(cleanup.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

async function attemptWithSecretsOnDisk(): Promise<{ invocation: HarnessInvocation; paths: string[] }> {
  const workspacePath = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-hygiene-ws-'));
  const attemptId = `att-${path.basename(workspacePath)}`;
  const secretsDir = path.join(os.tmpdir(), 'eve', 'job-secrets', attemptId);
  const keyDir = path.join(os.tmpdir(), 'eve', 'worker-secrets', attemptId);
  cleanup.push(workspacePath, secretsDir, keyDir);
  await fs.mkdir(secretsDir, { recursive: true });
  await fs.writeFile(path.join(secretsDir, 'SERVICE_ACCOUNT_JSON'), '{"private_key":"x"}');
  await fs.mkdir(keyDir, { recursive: true });
  await fs.writeFile(path.join(keyDir, 'git_ssh_key'), 'ssh-key-material');
  const invocation = {
    jobId: 'proj-a1b2c3d4', attemptId, projectId: 'proj_1', text: '', workspacePath,
  } as unknown as HarnessInvocation;
  return { invocation, paths: [secretsDir, keyDir] };
}

async function exists(target: string): Promise<boolean> {
  return fs.stat(target).then(() => true, () => false);
}

describe('worker job hygiene', () => {
  const outcomes: Array<[string, (phase: { value: string }) => Promise<unknown>]> = [
    ['succeeds', async () => ({ success: true, exitCode: 0 })],
    ['fails', async () => ({ success: false, exitCode: 1, error: 'harness exited 1' })],
    ['throws', async () => { throw new Error('clone failed'); }],
    ['is cancelled', async (phase) => { phase.value = 'cancelled'; return { success: true, exitCode: 0 }; }],
  ];

  it.each(outcomes)('deletes the attempt\'s secret files when the job %s', async (_label, outcome) => {
    const { invocation, paths } = await attemptWithSecretsOnDisk();
    const service = new InvokeService(null as never);
    const phase = { value: 'active' };
    (service as any).jobs = { findById: vi.fn(async () => ({ phase: phase.value })) };
    vi.spyOn(service as any, 'executeCancellable').mockImplementation(() => outcome(phase));

    await service.execute(invocation).catch(() => undefined);

    for (const target of paths) expect(await exists(target)).toBe(false);
  });

  it('deletes the attempt\'s secret files when the job was cancelled before it started', async () => {
    const { invocation, paths } = await attemptWithSecretsOnDisk();
    const service = new InvokeService(null as never);
    (service as any).jobs = { findById: vi.fn(async () => ({ phase: 'cancelled' })) };

    await service.execute(invocation);

    for (const target of paths) expect(await exists(target)).toBe(false);
  });
});
