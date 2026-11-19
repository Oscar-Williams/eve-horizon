import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation, SecurityProfile } from '@eve/shared';

/**
 * Rule harness.checkout_settings (P2-9) where the worker runs a harness: the
 * project's profile decides; routing settings the checkout supplies are
 * recorded under audit and strict, and under strict eve-agent-cli is told to
 * keep them out, or a harness with no way to is refused before it starts.
 */

const mocks = vi.hoisted(() => ({
  profile: 'legacy' as string,
  decide: vi.fn(),
  spawned: [] as Array<Record<string, string | undefined>>,
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  governingSecurityProfile: vi.fn(async () => mocks.profile),
  decideSecurityRule: mocks.decide,
}));
vi.mock('@eve/shared', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/shared')>()),
  loadConfig: vi.fn().mockReturnValue({ EVE_API_URL: 'http://localhost:4801' }),
  writeCoordinationInbox: vi.fn().mockResolvedValue(undefined),
  writeThreadContext: vi.fn().mockResolvedValue(undefined),
  writeCarryoverContext: vi.fn().mockResolvedValue(undefined),
  createJobUserHome: vi.fn().mockResolvedValue(os.tmpdir()),
  writeEveCredentials: vi.fn().mockResolvedValue(null),
  spawnHarnessProcess: vi.fn((_binary: string, _args: string[], options: { env: Record<string, string | undefined> }) => {
    mocks.spawned.push(options.env);
    throw new Error('spawned');
  }),
}));

import { InvokeService } from './invoke.service';

const made: string[] = [];
afterEach(() => {
  for (const dir of made.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  mocks.spawned.length = 0;
  mocks.decide.mockReset();
});

function checkout(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eve-worker-checkout-'));
  made.push(root);
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), content);
  }
  return root;
}

async function run(profile: SecurityProfile, harness: string, workspace: string): Promise<unknown> {
  mocks.profile = profile;
  mocks.decide.mockResolvedValue(profile);
  const service = new InvokeService(vi.fn(async () => []) as never);
  const inner = service as unknown as Record<string, unknown>;
  inner.resolveEveAgentCliCommand = vi.fn().mockResolvedValue({ binary: 'eve-agent-cli', prefixArgs: [] });
  inner.resolveBudgetEnforcementConfig = vi.fn().mockResolvedValue(null);
  inner.logLifecycleEvent = vi.fn().mockResolvedValue(undefined);
  inner.buildCoordinationDb = vi.fn().mockReturnValue({});
  inner.buildCarryoverContextDb = vi.fn().mockReturnValue({});
  const invocation = { jobId: 'shop-9', attemptId: '00000000-0000-0000-0000-000000000009', projectId: 'proj_shop', text: 'go' } as unknown as HarnessInvocation;
  return (inner.executeEveAgentCli as Function).call(service, invocation, { harness, permission: 'yolo', env: {} }, workspace)
    .catch((error: Error) => error.message);
}

describe('checkout settings where the worker runs a harness', () => {
  const routed = () => checkout({ '.env': 'GOOGLE_GEMINI_BASE_URL=https://relay.eve.example\n' });

  it('under audit records the routing names and starts the harness as before', async () => {
    expect(await run('audit', 'gemini', routed())).toBe('spawned');
    expect(mocks.decide).toHaveBeenCalledWith(expect.anything(), 'harness.checkout_settings', expect.objectContaining({
      projectId: 'proj_shop', governing: 'project',
      detail: expect.objectContaining({ settings: 'GOOGLE_GEMINI_BASE_URL', files: '.env' }),
    }));
    expect(mocks.spawned[0]?.EVE_HARNESS_CHECKOUT_SETTINGS).toBeUndefined();
  });

  it('under strict tells eve-agent-cli to keep checkout routing out', async () => {
    expect(await run('strict', 'gemini', routed())).toBe('spawned');
    expect(mocks.spawned[0]?.EVE_HARNESS_CHECKOUT_SETTINGS).toBe('strict');
  });

  it('under strict refuses a harness with no confirmed way, before it starts', async () => {
    expect(await run('strict', 'code', checkout({}))).toMatch(/harness\.checkout_settings/);
    expect(mocks.spawned).toHaveLength(0);
  });

  it('under legacy reads nothing', async () => {
    expect(await run('legacy', 'gemini', routed())).toBe('spawned');
    expect(mocks.decide).not.toHaveBeenCalled();
    expect(mocks.spawned[0]?.EVE_HARNESS_CHECKOUT_SETTINGS).toBeUndefined();
  });
});
