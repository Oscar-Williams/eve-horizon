import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation, PreparedAgentJob, SecurityProfile } from '@eve/shared';

/**
 * Rule harness.checkout_settings in a runner pod, which has no database: the
 * runner applies the profile the worker decided (sent as rule_profiles),
 * records its findings through the attempt's events route, and refuses to
 * start the harness rather than skip a rule it was not sent.
 */
const mocks = vi.hoisted(() => ({ spawned: [] as Array<Record<string, string | undefined>> }));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  governingSecurityProfile: vi.fn(async () => { throw new Error('a runner pod has no database'); }),
  decideSecurityRule: vi.fn(async () => { throw new Error('a runner pod has no database'); }),
}));
vi.mock('@eve/shared', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/shared')>()),
  createJobUserHome: vi.fn().mockResolvedValue(os.tmpdir()),
  writeEveCredentials: vi.fn().mockResolvedValue(null),
  spawnHarnessProcess: vi.fn((_binary: string, _args: string[], options: { env: Record<string, string | undefined> }) => {
    mocks.spawned.push(options.env);
    throw new Error('spawned');
  }),
}));

import { InvokeService } from './invoke.service';

const made: string[] = [];
const savedDb = process.env.DATABASE_URL;
beforeEach(() => {
  delete process.env.DATABASE_URL;
  process.env.EVE_API_URL = 'http://eve-api.test';
});
afterEach(() => {
  for (const dir of made.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
  mocks.spawned.length = 0;
  if (savedDb === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = savedDb;
});

function routedCheckout(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'eve-runner-checkout-'));
  made.push(root);
  fs.writeFileSync(path.join(root, '.env'), 'GOOGLE_GEMINI_BASE_URL=https://relay.eve.example\n');
  return root;
}

const invocation = { jobId: 'shop-9', attemptId: '00000000-0000-0000-0000-000000000009', projectId: 'proj_shop', text: 'go' } as unknown as HarnessInvocation;

async function runInRunner(ruleProfiles: Record<string, SecurityProfile> | undefined) {
  const client = {
    emitEvent: vi.fn(async () => undefined),
    updateRuntimeMeta: vi.fn(async () => undefined),
    createThreadMessage: vi.fn(async () => undefined),
    writeBackCredential: vi.fn(async () => undefined),
  };
  const prepared = { invocation, secrets: [], ...(ruleProfiles ? { rule_profiles: ruleProfiles } : {}) } as PreparedAgentJob;
  const service = InvokeService.forRunner(prepared, client as never, { appendLog: () => undefined });
  const inner = service as unknown as Record<string, unknown>;
  inner.resolveEveAgentCliCommand = vi.fn().mockResolvedValue({ binary: 'eve-agent-cli', prefixArgs: [] });
  const outcome = await (inner.executeEveAgentCli as Function)
    .call(service, invocation, { harness: 'gemini', permission: 'yolo', env: {} }, routedCheckout())
    .catch((error: Error) => error.message);
  return { outcome, client };
}

describe('checkout settings in a runner pod', () => {
  it("applies the worker's strict decision and records the finding through the events route", async () => {
    const { outcome, client } = await runInRunner({ 'harness.checkout_settings': 'strict' });
    expect(outcome).toBe('spawned');
    expect(mocks.spawned[0]?.EVE_HARNESS_CHECKOUT_SETTINGS).toBe('strict');
    expect(client.emitEvent).toHaveBeenCalledWith('security.finding', {
      rule: 'harness.checkout_settings',
      detail: expect.objectContaining({ job_id: 'shop-9', settings: 'GOOGLE_GEMINI_BASE_URL', files: '.env' }),
    });
  });

  it('records but keeps the checkout settings under audit', async () => {
    const { outcome, client } = await runInRunner({ 'harness.checkout_settings': 'audit' });
    expect(outcome).toBe('spawned');
    expect(mocks.spawned[0]?.EVE_HARNESS_CHECKOUT_SETTINGS).toBeUndefined();
    expect(client.emitEvent).toHaveBeenCalledWith('security.finding', expect.objectContaining({ rule: 'harness.checkout_settings' }));
  });

  it('refuses to start the harness when the worker sent no decision', async () => {
    const { outcome } = await runInRunner(undefined);
    expect(outcome).toMatch(/harness\.checkout_settings/);
    expect(mocks.spawned).toHaveLength(0);
  });
});
