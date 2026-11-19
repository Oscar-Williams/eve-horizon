import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createSign, generateKeyPairSync } from 'node:crypto';
import { BadRequestException, ConflictException, ForbiddenException, UnauthorizedException } from '@nestjs/common';
import type { SecurityProfile } from '@eve/shared';
import { AttemptsRunnerController } from './attempts.runner.controller';
import { RunnerAttemptsService } from './runner-attempts.service';

/**
 * Runner routes take the attempt's own job token and are push-only. Job
 * shop-1 runs attempt att-a; att-b is another attempt (of job shop-2). The
 * token for att-a reaches att-a's routes only, and only while att-a runs.
 */
const m = vi.hoisted(() => ({
  liveness: {} as Record<string, { phase: string; running_attempt_id: string | null }>,
  jobs: {} as Record<string, Record<string, unknown>>,
  threads: {} as Record<string, { project_id: string | null }>,
  logs: [] as Array<{ attemptId: string; type: string; content: unknown }>,
  meta: [] as Array<{ attemptId: string; meta: Record<string, unknown> }>,
  events: [] as Array<Record<string, unknown>>,
  messages: [] as Array<Record<string, unknown>>,
  results: new Map<string, unknown>(),
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    jobQueries: vi.fn(() => ({
      getTokenLiveness: vi.fn(async (id: string) => m.liveness[id] ?? null),
      findById: vi.fn(async (id: string) => m.jobs[id] ?? null),
      updateRuntimeMeta: vi.fn(async (attemptId: string, meta: Record<string, unknown>) => { m.meta.push({ attemptId, meta }); return {}; }),
    })),
    executionLogQueries: vi.fn(() => ({
      appendLog: vi.fn(async (attemptId: string, type: string, content: unknown) => { m.logs.push({ attemptId, type, content }); }),
    })),
    eventQueries: vi.fn(() => ({ create: vi.fn(async (event: Record<string, unknown>) => { m.events.push(event); return event; }) })),
    threadQueries: vi.fn(() => ({ findById: vi.fn(async (id: string) => m.threads[id] ?? null) })),
    threadMessageQueries: vi.fn(() => ({ create: vi.fn(async (msg: Record<string, unknown>) => { m.messages.push(msg); return msg; }) })),
    runnerResultQueries: vi.fn(() => ({
      record: vi.fn(async (attemptId: string, result: unknown) => {
        if (m.results.has(attemptId)) return false;
        m.results.set(attemptId, result);
        return true;
      }),
      find: vi.fn(async (attemptId: string) => (m.results.has(attemptId) ? { result: m.results.get(attemptId), received_at: new Date() } : null)),
    })),
  };
});

const TOKENS: Record<string, Record<string, unknown>> = {
  'token-a': { type: 'job', job_id: 'shop-1', attempt_id: 'att-a', project_id: 'proj_shop', org_id: 'org_acme', user_id: 'user_alice' },
  'token-b': { type: 'job', job_id: 'shop-2', attempt_id: 'att-b', project_id: 'proj_shop', org_id: 'org_acme', user_id: 'user_alice' },
  'token-unbound': { type: 'job', job_id: 'shop-1', project_id: 'proj_shop', org_id: 'org_acme', user_id: 'user_alice' },
};

const issuer = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwks = { keys: [{ ...issuer.publicKey.export({ format: 'jwk' }), kid: 'k1', alg: 'RS256' }] };

function idToken(account: string): string {
  const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64url');
  const body = `${enc({ alg: 'RS256', kid: 'k1' })}.${enc({ iss: 'https://auth.openai.com', 'https://api.openai.com/auth': { chatgpt_account_id: account } })}`;
  const signer = createSign('RSA-SHA256');
  signer.update(body);
  return `${body}.${signer.sign(issuer.privateKey).toString('base64url')}`;
}

function codexAuth(account: string, opts: { plainAccount?: string; refresh?: string } = {}): string {
  return Buffer.from(JSON.stringify({ tokens: { access_token: `at-${opts.refresh ?? '1'}`, refresh_token: 'rt',
    account_id: opts.plainAccount ?? account, id_token: idToken(account) } })).toString('base64');
}

let profiles: Record<string, SecurityProfile>;
let stored: { key: string; value: string; type: string; scope_type: 'org' | 'project' | 'user'; scope_id: string } | null;
const secrets = {
  resolveForJob: vi.fn(async () => (stored ? [stored] : [])),
  // SecretsService.mayJobWriteSecret: rule secrets.job_org_write for an org-scope write.
  mayJobWriteSecret: vi.fn(async (_caller: Record<string, unknown>, scope: string) => scope !== 'org' || profiles['secrets.job_org_write'] !== 'strict'),
  updateIfExists: vi.fn(async () => true),
  create: vi.fn(async () => ({})),
};

function controller() {
  const auth = {
    verifyJobToken: vi.fn((token: string) => {
      const payload = TOKENS[token];
      if (!payload) throw new UnauthorizedException('Invalid token');
      return payload;
    }),
  };
  const security = { decide: vi.fn(async (rule: string) => profiles[rule] ?? 'legacy') };
  const service = new RunnerAttemptsService(auth as never, {} as never, secrets as never, security as never, async () => jwks);
  return { controller: new AttemptsRunnerController(service), security };
}

beforeEach(() => {
  m.liveness = {
    'shop-1': { phase: 'active', running_attempt_id: 'att-a' },
    'shop-2': { phase: 'active', running_attempt_id: 'att-b' },
  };
  m.jobs = {
    'shop-1': { id: 'shop-1', project_id: 'proj_shop', parent_id: 'lead-1', hints: { thread_id: 'thr_chat' } },
    'lead-1': { id: 'lead-1', project_id: 'proj_shop', hints: { coordination: { thread_id: 'thr_coord' } } },
    'shop-2': { id: 'shop-2', project_id: 'proj_shop', hints: {} },
  };
  m.threads = { thr_chat: { project_id: 'proj_shop' }, thr_coord: { project_id: 'proj_shop' }, thr_other: { project_id: 'proj_other' } };
  m.logs = []; m.meta = []; m.events = []; m.messages = []; m.results = new Map();
  profiles = {};
  stored = { key: 'CODEX_AUTH_JSON_B64', value: codexAuth('acct_acme'), type: 'env_var', scope_type: 'org', scope_id: 'org_acme' };
  secrets.resolveForJob.mockClear(); secrets.updateIfExists.mockClear(); secrets.create.mockClear(); secrets.mayJobWriteSecret.mockClear();
});

describe('runner routes: the attempt token', () => {
  it("lets attempt A's token push only to attempt A", async () => {
    const { controller: c } = controller();
    await expect(c.appendLogs('shop-2', 'att-b', 'Bearer token-a', { entries: [{ type: 'log', content: {} }] }))
      .rejects.toBeInstanceOf(ForbiddenException);
    await expect(c.pushResult('shop-2', 'att-b', 'Bearer token-a', { success: true, exit_code: 0 }))
      .rejects.toBeInstanceOf(ForbiddenException);
    await expect(c.appendLogs('shop-1', 'att-b', 'Bearer token-a', { entries: [{ type: 'log', content: {} }] }))
      .rejects.toBeInstanceOf(ForbiddenException);
    expect(m.logs).toEqual([]);
    expect(m.results.size).toBe(0);

    await c.appendLogs('shop-1', 'att-a', 'Bearer token-a', { entries: [{ type: 'log', content: { line: 'ok' } }] });
    expect(m.logs).toEqual([{ attemptId: 'att-a', type: 'log', content: { line: 'ok' } }]);
  });

  it('refuses a job token not bound to an attempt, and no token at all', async () => {
    const { controller: c } = controller();
    await expect(c.appendLogs('shop-1', 'att-a', 'Bearer token-unbound', { entries: [] })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(c.appendLogs('shop-1', 'att-a', undefined, { entries: [] })).rejects.toBeInstanceOf(UnauthorizedException);
  });

  it('stops working once attempt A has ended', async () => {
    const { controller: c } = controller();
    m.liveness['shop-1'] = { phase: 'active', running_attempt_id: null };
    await expect(c.appendLogs('shop-1', 'att-a', 'Bearer token-a', { entries: [{ type: 'log', content: {} }] }))
      .rejects.toBeInstanceOf(UnauthorizedException);
    await expect(c.pushResult('shop-1', 'att-a', 'Bearer token-a', { success: true, exit_code: 0 }))
      .rejects.toBeInstanceOf(UnauthorizedException);
  });
});

describe('runner routes: the result', () => {
  it('takes one result per attempt', async () => {
    const { controller: c } = controller();
    await c.pushResult('shop-1', 'att-a', 'Bearer token-a', { success: true, exit_code: 0, result_text: 'done' });
    await expect(c.pushResult('shop-1', 'att-a', 'Bearer token-a', { success: false, exit_code: 1 }))
      .rejects.toBeInstanceOf(ConflictException);
    expect(m.results.get('att-a')).toMatchObject({ success: true, result_text: 'done' });
  });
});

describe('runner routes: pushed state', () => {
  it('writes only the runtime fields a runner reports', async () => {
    const { controller: c } = controller();
    await c.updateRuntimeMeta('shop-1', 'att-a', 'Bearer token-a', { meta: { resource_index_path: '.eve/resources/index.json' } });
    expect(m.meta).toEqual([{ attemptId: 'att-a', meta: { resource_index_path: '.eve/resources/index.json' } }]);
    await expect(c.updateRuntimeMeta('shop-1', 'att-a', 'Bearer token-a', { meta: { pod_name: 'eve-worker-0' } }))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it("posts thread messages only to the job's own chat or coordination thread", async () => {
    const { controller: c } = controller();
    await c.createThreadMessage('shop-1', 'att-a', 'Bearer token-a', { thread_id: 'thr_coord', body: 'progress', actor_type: 'agent', actor_id: 'shop' });
    await c.createThreadMessage('shop-1', 'att-a', 'Bearer token-a', { thread_id: 'thr_chat', body: 'reply', actor_type: 'agent', actor_id: 'shop' });
    await expect(c.createThreadMessage('shop-1', 'att-a', 'Bearer token-a', { thread_id: 'thr_other', body: 'x', actor_type: 'agent', actor_id: 'shop' }))
      .rejects.toBeInstanceOf(ForbiddenException);
    expect(m.messages.map((msg) => [msg.thread_id, msg.job_id, msg.direction])).toEqual([
      ['thr_coord', 'shop-1', 'outbound'], ['thr_chat', 'shop-1', 'outbound'],
    ]);
  });

  it('emits only resource hydration events, for its own project', async () => {
    const { controller: c } = controller();
    await c.emitEvent('shop-1', 'att-a', 'Bearer token-a', { type: 'system.resource.hydration.completed', payload: { resolved_count: 1 } });
    await expect(c.emitEvent('shop-1', 'att-a', 'Bearer token-a', { type: 'runner.completed', payload: {} }))
      .rejects.toBeInstanceOf(BadRequestException);
    expect(m.events).toEqual([expect.objectContaining({ project_id: 'proj_shop', type: 'system.resource.hydration.completed' })]);
  });
});

describe('runner routes: the Codex credential write-back', () => {
  it('refuses an auth.json whose signed account differs, whatever its plain account_id says', async () => {
    const { controller: c } = controller();
    const forged = codexAuth('acct_other', { plainAccount: 'acct_acme', refresh: '2' });
    await expect(c.writeBackCredential('shop-1', 'att-a', 'Bearer token-a', { key: 'CODEX_AUTH_JSON_B64', value: forged }))
      .rejects.toBeInstanceOf(ConflictException);
    expect(secrets.updateIfExists).not.toHaveBeenCalled();
    expect(secrets.create).not.toHaveBeenCalled();
  });

  it('refuses any other key', async () => {
    const { controller: c } = controller();
    await expect(c.writeBackCredential('shop-1', 'att-a', 'Bearer token-a', { key: 'GITHUB_TOKEN', value: 'x' }))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it("writes a refreshed auth.json to the secret's own scope under audit, and records an org write", async () => {
    profiles = { 'secrets.job_org_write': 'audit' };
    const { controller: c } = controller();
    const refreshed = codexAuth('acct_acme', { refresh: '2' });
    await c.writeBackCredential('shop-1', 'att-a', 'Bearer token-a', { key: 'CODEX_AUTH_JSON_B64', value: refreshed });
    expect(secrets.updateIfExists).toHaveBeenCalledWith('org', 'org_acme', 'CODEX_AUTH_JSON_B64', refreshed);
    expect(secrets.mayJobWriteSecret).toHaveBeenCalledWith(
      expect.objectContaining({ is_job_token: true, job_id: 'shop-1', project_id: 'proj_shop' }), 'org', 'CODEX_AUTH_JSON_B64');
  });

  it('writes it to project scope only under strict', async () => {
    profiles = { 'secrets.job_org_write': 'strict' };
    const { controller: c } = controller();
    const refreshed = codexAuth('acct_acme', { refresh: '2' });
    await c.writeBackCredential('shop-1', 'att-a', 'Bearer token-a', { key: 'CODEX_AUTH_JSON_B64', value: refreshed });
    expect(secrets.updateIfExists).not.toHaveBeenCalledWith('org', expect.anything(), expect.anything(), expect.anything());
    expect(secrets.create).toHaveBeenCalledWith('project', 'proj_shop', expect.objectContaining({ key: 'CODEX_AUTH_JSON_B64', value: refreshed }));
  });
});

describe('runner routes: findings for rules the runner applies', () => {
  it('records a finding for an allowed rule as the job, and refuses any other rule', async () => {
    const { controller: c, security } = controller();
    await c.emitEvent('shop-1', 'att-a', 'Bearer token-a', { type: 'security.finding', payload: { rule: 'harness.checkout_settings', detail: { settings: 'model' } } });
    expect(security.decide).toHaveBeenCalledWith('harness.checkout_settings', expect.objectContaining({
      projectId: 'proj_shop', governing: 'project', detail: expect.objectContaining({ settings: 'model', job_id: 'shop-1' }),
    }));
    await expect(c.emitEvent('shop-1', 'att-a', 'Bearer token-a', { type: 'security.finding', payload: { rule: 'secrets.value_read', detail: {} } }))
      .rejects.toBeInstanceOf(BadRequestException);
  });
});
