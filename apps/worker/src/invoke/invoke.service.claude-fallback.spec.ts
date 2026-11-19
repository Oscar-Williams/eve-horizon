import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation } from '@eve/shared';
import { InvokeService } from './invoke.service.js';

let home: string;
beforeEach(async () => {
  home = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-claude-fallback-'));
  await fs.mkdir(path.join(home, '.claude'), { recursive: true });
  await fs.writeFile(
    path.join(home, '.claude', '.credentials.json'),
    JSON.stringify({ claudeAiOauth: { accessToken: 'sk-ant-oat01-service-home', expiresAt: Date.now() + 3_600_000 } }),
  );
  vi.stubEnv('HOME', home);
});
afterEach(async () => {
  vi.unstubAllEnvs();
  await fs.rm(home, { recursive: true, force: true });
});

function decide(invocation: Partial<HarnessInvocation>) {
  const service = new InvokeService(null as never);
  return (service as any).resolveClaudeAuthDecision([], {}, invocation);
}

describe("the worker's Claude credentials file in its own HOME", () => {
  it('still serves a job without a secrets allowlist', async () => {
    expect(await decide({})).not.toBeNull();
  });

  it('never serves a job with a secrets allowlist', async () => {
    expect(await decide({ secrets_allowlist: ['SHOP_SIGNING_KEY'] })).toBeNull();
  });
});

describe("a job whose credentials come from secrets only (the project's strict profile)", () => {
  it('gets neither the credentials file nor a key from the environment', async () => {
    const service = new InvokeService(null as never);
    const decision = await (service as any).resolveClaudeAuthDecision(
      [],
      { ANTHROPIC_API_KEY: 'sk-ant-api03-environment' },
      { credentials_from_secrets_only: true },
    );

    expect(decision).toBeNull();
  });

  it('still gets a credential its own secrets hold', async () => {
    const service = new InvokeService(null as never);
    const decision = await (service as any).resolveClaudeAuthDecision(
      [{ key: 'ANTHROPIC_API_KEY', value: 'sk-ant-api03-project', type: 'env_var', scope_type: 'project' }],
      {},
      { credentials_from_secrets_only: true },
    );

    expect(decision).not.toBeNull();
  });
});

