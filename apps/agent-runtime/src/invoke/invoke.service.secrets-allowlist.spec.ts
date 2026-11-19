import { afterEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation, SecretResolveItem } from '@eve/shared';

const resolved = vi.hoisted(() => ({ secrets: [] as unknown[] }));

vi.mock('@eve/shared', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/shared')>()),
  resolveSecrets: vi.fn(async () => resolved.secrets),
}));

import { InvokeService } from './invoke.service.js';

const TOKEN = 'ghs_exampleInstallationToken123';

function secret(key: string, value = `${key}-value`): SecretResolveItem {
  return { key, value, type: 'env_var', scope_type: 'project', scope_id: 'proj_1' } as SecretResolveItem;
}

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllEnvs();
});

async function contextFor(secrets_allowlist?: string[], extra: Record<string, unknown> = {}) {
  resolved.secrets = [secret('ANTHROPIC_API_KEY'), secret('GITHUB_TOKEN', TOKEN), secret('SHOP_SIGNING_KEY'), secret('SMTP_PASSWORD')];
  const invocation = {
    jobId: 'shop-a1b2c3d4', attemptId: `att-${Math.random().toString(36).slice(2)}`, projectId: 'proj_1', text: 'review',
    workspacePath: '/tmp/eve-allowlist-test', repoUrl: 'https://github.com/org/repo.git',
    ...(secrets_allowlist ? { secrets_allowlist } : {}),
    ...extra,
  } as unknown as HarnessInvocation;
  const service = new InvokeService(null as never);
  (service as any).jobs = { markExecutionStarted: vi.fn(), updateRuntimeMeta: vi.fn() };
  vi.spyOn(service as any, 'applyManifestDefaults').mockImplementation(async (inv) => inv);
  let captured: any;
  vi.spyOn(service as any, 'prepareRepo').mockImplementation(async (ctx) => { captured = ctx; throw new Error('stop'); });
  const cancellation = { signal: new AbortController().signal, check: vi.fn(), stop: vi.fn() };
  // The inline path's workspace cleanup reads service config, absent here; the context is captured first.
  const result = await (service as any).executeCancellable(invocation, cancellation).catch(() => undefined);
  return Object.assign(captured ?? {}, { result, cloned: Boolean(captured) });
}

describe('agent runtime secrets allowlist', () => {
  it('hands the job every resolved secret when no allowlist is declared (unchanged)', async () => {
    const ctx = await contextFor();
    expect(ctx.resolvedSecrets.map((s: SecretResolveItem) => s.key)).toEqual(['ANTHROPIC_API_KEY', 'GITHUB_TOKEN', 'SHOP_SIGNING_KEY', 'SMTP_PASSWORD']);
    expect(ctx.gitAuth?.cloneUrl).toContain(TOKEN);
  });

  it('hands the job only the allowlisted secrets', async () => {
    const ctx = await contextFor(['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY']);
    expect(ctx.resolvedSecrets.map((s: SecretResolveItem) => s.key)).toEqual(['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY']);
  });

  it('still clones with a git token the allowlist leaves out, without putting it in the clone URL', async () => {
    const ctx = await contextFor(['ANTHROPIC_API_KEY']);
    expect(ctx.gitAuth?.cloneUrl).toBeUndefined();
    expect(JSON.stringify(ctx.gitAuth?.env ?? {})).toContain(Buffer.from(`x-access-token:${TOKEN}`).toString('base64'));
    expect(ctx.resolvedSecrets.map((s: SecretResolveItem) => s.key)).not.toContain('GITHUB_TOKEN');
  });

  it('refuses, before cloning, a job that would push with a git token its allowlist leaves out', async () => {
    // The inline path's workspace cleanup loads service config, which needs a database URL.
    vi.stubEnv('DATABASE_URL', 'postgres://eve:eve@localhost:5432/eve');
    const ctx = await contextFor(['ANTHROPIC_API_KEY'], { git: { push: 'on_success' } });
    expect(ctx.cloned).toBe(false);
    expect(ctx.result).toMatchObject({ success: false, error: expect.stringContaining('secrets allowlist') });
  });
});
