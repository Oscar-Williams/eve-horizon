import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { watchJobCancellation, type HarnessInvocation } from '@eve/shared';
import { InvokeService } from './invoke.service.js';

vi.mock('@eve/shared', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/shared')>()),
  resolveBudgetEnforcementConfig: async () => null,
}));

const cleanup: string[] = [];
afterEach(async () => {
  vi.restoreAllMocks();
  await Promise.all(cleanup.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

async function attemptWithSecretsOnDisk(): Promise<{ invocation: HarnessInvocation; paths: string[] }> {
  const workspacePath = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-hygiene-ws-'));
  const attemptId = `att-${path.basename(workspacePath)}`;
  const secretsDir = path.join(os.tmpdir(), 'eve', 'job-secrets', attemptId);
  const sshKey = path.join(workspacePath, '.eve', 'git_ssh_key');
  cleanup.push(workspacePath, secretsDir);
  await fs.mkdir(secretsDir, { recursive: true });
  await fs.writeFile(path.join(secretsDir, 'SERVICE_ACCOUNT_JSON'), '{"private_key":"x"}');
  await fs.mkdir(path.dirname(sshKey), { recursive: true });
  await fs.writeFile(sshKey, 'ssh-key-material');
  const invocation = {
    jobId: 'proj-a1b2c3d4', attemptId, projectId: 'proj_1', text: '', workspacePath,
  } as unknown as HarnessInvocation;
  return { invocation, paths: [secretsDir, sshKey] };
}

async function exists(target: string): Promise<boolean> {
  return fs.stat(target).then(() => true, () => false);
}

describe('agent job hygiene', () => {
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

  it('gives the harness its prompt on stdin, never on the command line', async () => {
    const service = new InvokeService(null as never);
    const prompt = 'Triage notice 4471: untrusted text from a tender portal';
    const args = (service as any).buildHarnessArgs({
      harness: 'claude', permission: 'yolo', workspace: '/workspace/repo', prompt,
    }) as string[];
    expect(args.join(' ')).not.toContain(prompt);

    const appended: Array<{ type: string; content: any }> = [];
    (service as any).logs = { appendLog: vi.fn(async (_id: string, type: string, content: unknown) => { appended.push({ type, content }); }) };
    const cancellation = await watchJobCancellation(async () => 'active', 50);
    const invocation = { jobId: 'job_1', attemptId: 'att_1', projectId: 'proj_1', text: prompt, workspacePath: os.tmpdir() } as unknown as HarnessInvocation;
    const ctx = { invocationWithOptions: invocation, lifecycleLogger: vi.fn().mockResolvedValue(undefined) };
    const plan = {
      isClaudeHarness: false, claudeAuthDecision: null,
      harnessOptionsResolved: { harness: 'claude', permission: 'yolo' },
      harnessBinary: { binary: process.execPath, prefixArgs: [] },
      harnessArgs: ['-e', `let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{console.log(JSON.stringify({type:'probe',stdin:s,argv:process.argv}));});`],
      prompt,
    };
    const setup = { startTime: Date.now(), logs: [], processEnv: { PATH: process.env.PATH } };
    const relay = { processEvent: vi.fn().mockResolvedValue(undefined), processLine: vi.fn().mockResolvedValue(undefined) };
    try {
      await (service as any).runHarness(ctx, plan, setup, relay, process.cwd(), cancellation);
    } finally { cancellation.stop(); }

    const probe = appended.find((entry) => entry.type === 'probe')?.content;
    expect(probe?.stdin).toBe(prompt);
    expect((probe?.argv as string[]).join(' ')).not.toContain(prompt);
  });
});
