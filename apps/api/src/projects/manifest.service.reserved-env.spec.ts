import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException, ForbiddenException } from '@nestjs/common';
import type { SecurityProfile } from '@eve/shared';
import { ManifestService } from './manifest.service';
import type { SecretsService } from '../secrets/secrets.service';
import type { SecurityService } from '../security/security.service';

/**
 * In-memory stand-ins for the tables manifest sync touches. Any query method
 * the test does not define resolves to [] for list-style names and null
 * otherwise, so the rest of sync runs as a no-op.
 */
const db = vi.hoisted(() => {
  const state = { xEveYaml: null as string | null };

  function stub<T extends object>(defined: T): T {
    return new Proxy(defined, {
      get(target, key, receiver) {
        if (typeof key !== 'string' || key in target) return Reflect.get(target, key, receiver);
        const fn = vi.fn(async () => (/^(list|findByProject$|find.*s$)/.test(key) ? [] : null));
        Reflect.set(target, key, fn);
        return fn;
      },
    });
  }

  const projects = stub({
    findById: vi.fn(async (id: string) => ({ id, org_id: 'org_a', slug: 'trg', auth_config: null })),
  });
  const manifests = stub({
    create: vi.fn(async (row: Record<string, unknown>) => ({ ...row, created_at: new Date(), updated_at: new Date() })),
  });
  const agentConfigs = stub({
    findLatestByProject: vi.fn(async () => (state.xEveYaml === null ? null : { x_eve_yaml: state.xEveYaml })),
  });

  return { state, projects, manifests, agentConfigs, stub };
});

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    projectQueries: vi.fn(() => db.projects),
    orgQueries: vi.fn(() => db.stub({})),
    membershipQueries: vi.fn(() => db.stub({})),
    projectManifestQueries: vi.fn(() => db.manifests),
    agentConfigQueries: vi.fn(() => db.agentConfigs),
    environmentQueries: vi.fn(() => db.stub({})),
    ingressAliasQueries: vi.fn(() => db.stub({})),
    customDomainQueries: vi.fn(() => db.stub({})),
    appLinkGrantQueries: vi.fn(() => db.stub({})),
    appLinkSubscriptionQueries: vi.fn(() => db.stub({})),
  };
});

/** A stand-in for SecurityService.gate: refuses under strict, records otherwise. */
function fakeSecurity(profile: SecurityProfile) {
  const gate = vi.fn(async (rule: string, _ctx: unknown, message?: string) => {
    if (profile === 'legacy') return 'allowed';
    if (profile === 'strict') throw new ForbiddenException(`${message ?? 'Refused'} (rule ${rule})`);
    return 'recorded';
  });
  return { gate, decide: vi.fn(async () => profile) };
}

function manifest(env: Record<string, string>, where: 'workflow' | 'pipeline' = 'workflow') {
  return JSON.stringify({
    schema: 'eve/compose/v2',
    ...(where === 'workflow'
      ? { workflows: { triage: { steps: [{ name: 'judge', agent: { prompt: 'Run' }, env_overrides: env }] } } }
      : { pipelines: { build: { steps: [{ name: 'run', action: { type: 'run', command: 'true' }, env_overrides: env }] } } }),
  });
}

async function sync(profile: SecurityProfile, yaml: string) {
  const security = fakeSecurity(profile);
  const service = new ManifestService(
    { begin: async (fn: (tx: unknown) => Promise<unknown>) => fn({}) } as never,
    {} as SecretsService,
    security as unknown as SecurityService,
  );
  const result = (service.syncManifest as (...args: unknown[]) => Promise<{ warnings?: string[] }>)(
    'proj_lab',
    { yaml },
    { user_id: 'user_alice' },
  );
  return { result, security };
}

describe('ManifestService.syncManifest: reserved env override names', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    db.state.xEveYaml = null;
  });

  it('refuses a model routing name with a literal value on every profile', async () => {
    const { result } = await sync('legacy', manifest({ ANTHROPIC_BASE_URL: 'https://models.example.test' }));

    await expect(result).rejects.toBeInstanceOf(BadRequestException);
  });

  it('refuses a code-loading name under strict, in a workflow step or a pipeline step', async () => {
    await expect((await sync('strict', manifest({ PYTHONPATH: '/opt/lib' }))).result).rejects.toBeInstanceOf(ForbiddenException);
    await expect((await sync('strict', manifest({ LD_PRELOAD: '/tmp/x.so' }, 'pipeline'))).result).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('records a code-loading name under audit and syncs', async () => {
    const { result, security } = await sync('audit', manifest({ PYTHONPATH: '/opt/lib' }));

    await expect(result).resolves.toBeDefined();
    expect(security.gate).toHaveBeenCalledWith(
      'harness.reserved_env',
      expect.objectContaining({ projectId: 'proj_lab', detail: expect.objectContaining({ keys: 'PYTHONPATH' }) }),
      expect.any(String),
    );
  });
});
