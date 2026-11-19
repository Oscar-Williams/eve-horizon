import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation, SecurityProfile } from '@eve/shared';

/**
 * Rule harness.checkout_settings (P2-9) in the agent runtime's inline runs,
 * which serve projects not yet on strict: routing settings the checkout
 * supplies are recorded under audit, and under strict eve-agent-cli keeps
 * them out, or a harness with no way to is refused.
 */

const mocks = vi.hoisted(() => ({ profile: 'legacy' as string, decide: vi.fn() }));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  governingSecurityProfile: vi.fn(async () => mocks.profile),
  decideSecurityRule: mocks.decide,
}));

import { InvokeService } from './invoke.service.js';

const made: string[] = [];
afterEach(() => {
  for (const dir of made.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  mocks.decide.mockReset();
});

function checkout(files: Record<string, string>): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eve-runtime-checkout-'));
  made.push(root);
  for (const [file, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(root, file)), { recursive: true });
    fs.writeFileSync(path.join(root, file), content);
  }
  return root;
}

async function plan(profile: SecurityProfile, harness: string, workspace: string) {
  mocks.profile = profile;
  mocks.decide.mockResolvedValue(profile);
  const service = new InvokeService(null as never);
  const invocation = {
    jobId: 'shop-4', attemptId: `att-${path.basename(workspace)}`, projectId: 'proj_shop', text: 'go',
    workspacePath: workspace, harness, permission: 'yolo',
  } as unknown as HarnessInvocation;
  const ctx = {
    invocationWithOptions: invocation,
    resolvedSecrets: [],
    execTimings: {},
    timePhase: (_name: string, fn: () => unknown) => fn(),
  };
  made.push(path.join(os.tmpdir(), 'eve', 'agent-homes', invocation.attemptId));
  return (service as any).resolveHarnessExecution(ctx, workspace, {}) as Promise<{ harnessOptionsResolved: { env?: Record<string, string> } }>;
}

describe('checkout settings in the agent runtime', () => {
  const routed = () => checkout({ '.env': 'HTTPS_PROXY=http://proxy.eve.example\n' });

  it('under audit records the routing names and changes nothing else', async () => {
    const resolved = await plan('audit', 'gemini', routed());
    expect(mocks.decide).toHaveBeenCalledWith(null, 'harness.checkout_settings', expect.objectContaining({
      projectId: 'proj_shop', detail: expect.objectContaining({ settings: 'HTTPS_PROXY' }),
    }));
    expect(resolved.harnessOptionsResolved.env?.EVE_HARNESS_CHECKOUT_SETTINGS).toBeUndefined();
  });

  it('under strict tells eve-agent-cli to keep checkout routing out', async () => {
    const resolved = await plan('strict', 'gemini', routed());
    expect(resolved.harnessOptionsResolved.env?.EVE_HARNESS_CHECKOUT_SETTINGS).toBe('strict');
  });

  it('under strict refuses a harness with no confirmed way', async () => {
    await expect(plan('strict', 'pi', checkout({}))).rejects.toThrow(/harness\.checkout_settings/);
  });
});
