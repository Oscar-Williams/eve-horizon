import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
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

function manifest(steps: Array<Record<string, unknown>>, inputs?: Record<string, unknown>) {
  return JSON.stringify({
    schema: 'eve/compose/v2',
    'x-eve': { agents: { config_path: 'agents/agents.yaml', profiles: { triage: [{ harness: 'claude' }] } } },
    workflows: { triage: { ...(inputs ? { inputs } : {}), steps } },
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
    'proj_trg',
    { yaml },
    { user_id: 'user_alice' },
  );
  return { result, security };
}

describe('ManifestService.syncManifest: harness profiles named by workflow steps', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    db.state.xEveYaml = null;
  });

  it('refuses under strict a step that names a profile nobody declares', async () => {
    const { result, security } = await sync('strict', manifest([
      { name: 'judge', agent: { name: 'triage', prompt: 'Run' }, harness_profile: 'missing' },
    ]));

    await expect(result).rejects.toBeInstanceOf(ForbiddenException);
    expect(security.gate).toHaveBeenCalledWith('harness.missing_profile', expect.objectContaining({
      projectId: 'proj_trg',
      governing: 'project',
    }), expect.any(String));
    expect(db.manifests.create).not.toHaveBeenCalled();
  });

  it('syncs under audit with a warning naming the profile', async () => {
    const { result, security } = await sync('audit', manifest([
      { name: 'judge', agent: { name: 'triage', prompt: 'Run' }, harness_profile: 'missing' },
    ]));

    const response = await result;
    expect(response.warnings?.join('\n')).toMatch(/harness profile "missing"/);
    expect(security.gate).toHaveBeenCalledWith('harness.missing_profile', expect.anything(), expect.any(String));
  });

  it('accepts a profile the manifest or the stored agents config declares', async () => {
    db.state.xEveYaml = 'agents:\n  profiles:\n    from-pack:\n      - harness: claude\n';
    const { result, security } = await sync('strict', manifest([
      { name: 'one', agent: { prompt: 'Run' }, harness_profile: 'triage' },
      { name: 'two', agent: { prompt: 'Run' }, harness_profile: 'from-pack' },
    ]));

    await expect(result).resolves.toBeTruthy();
    expect(security.gate).not.toHaveBeenCalled();
  });

  it('leaves a templated profile name to run time', async () => {
    const { result, security } = await sync('strict', manifest([
      { name: 'one', agent: { prompt: 'Run' }, harness_profile: '${inputs.profile}' },
    ], { profile: { default: 'triage' } }));

    await expect(result).resolves.toBeTruthy();
    expect(security.gate).not.toHaveBeenCalled();
  });
});
