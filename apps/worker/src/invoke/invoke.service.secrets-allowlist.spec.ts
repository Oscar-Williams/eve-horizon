import * as os from 'node:os';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation, SecretResolveItem } from '@eve/shared';
import { InvokeService } from './invoke.service.js';

const TOKEN = 'ghs_exampleInstallationToken123';

function secret(key: string, value = `${key}-value`): SecretResolveItem {
  return { key, value, type: 'env_var', scope_type: 'project', scope_id: 'proj_1' } as SecretResolveItem;
}

afterEach(() => vi.restoreAllMocks());

async function runUntilSecretsMaterialize(secrets_allowlist?: string[]) {
  const invocation = {
    jobId: 'opps-a1b2c3d4', attemptId: `att-${Math.random().toString(36).slice(2)}`, projectId: 'proj_1', text: 'triage',
    workspacePath: '/tmp/eve-allowlist-test', repoUrl: 'https://github.com/org/repo.git',
    ...(secrets_allowlist ? { secrets_allowlist } : {}),
  } as unknown as HarnessInvocation;
  const service = new InvokeService(null as never);
  (service as any).jobs = { markExecutionStarted: vi.fn(), updateRuntimeMeta: vi.fn() };
  vi.spyOn(service as any, 'applyManifestDefaults').mockImplementation(async (inv) => inv);
  vi.spyOn(service as any, 'logLifecycleEvent').mockResolvedValue(undefined);
  vi.spyOn(service as any, 'resolveSecrets').mockResolvedValue([
    secret('ANTHROPIC_API_KEY'), secret('GITHUB_TOKEN', TOKEN), secret('OPPS_SIGNING_KEY'), secret('SMTP_PASSWORD'),
  ]);
  const seen: { gitAuth?: any; secrets?: SecretResolveItem[] } = {};
  vi.spyOn(service as any, 'prepareWorkspace').mockImplementation(async (_inv, gitAuth) => {
    seen.gitAuth = gitAuth;
    return { repoPath: os.tmpdir(), hadRepoPath: true };
  });
  vi.spyOn(service as any, 'materializeSecrets').mockImplementation(async (_repo, _inv, secrets) => {
    seen.secrets = secrets as SecretResolveItem[];
    throw new Error('stop');
  });
  const cancellation = { signal: new AbortController().signal, check: vi.fn(), stop: vi.fn() };
  // The inline path's workspace cleanup reads service config, absent here; the context is captured first.
  await (service as any).executeCancellable(invocation, cancellation).catch(() => undefined);
  return seen;
}

describe('worker secrets allowlist', () => {
  it('hands the job every resolved secret when no allowlist is declared (unchanged)', async () => {
    const seen = await runUntilSecretsMaterialize();
    expect(seen.secrets?.map((s) => s.key)).toEqual(['ANTHROPIC_API_KEY', 'GITHUB_TOKEN', 'OPPS_SIGNING_KEY', 'SMTP_PASSWORD']);
    expect(seen.gitAuth?.cloneUrl).toContain(TOKEN);
  });

  it('hands the job only the allowlisted secrets and clones without the token in the URL', async () => {
    const seen = await runUntilSecretsMaterialize(['ANTHROPIC_API_KEY']);
    expect(seen.secrets?.map((s) => s.key)).toEqual(['ANTHROPIC_API_KEY']);
    expect(seen.gitAuth?.cloneUrl).toBeUndefined();
    expect(JSON.stringify(seen.gitAuth?.env ?? {})).toContain(Buffer.from(`x-access-token:${TOKEN}`).toString('base64'));
  });
});
