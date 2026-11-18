import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  profile: 'legacy' as 'legacy' | 'audit' | 'strict',
  decide: vi.fn(),
  appendLog: vi.fn(async () => undefined),
  agentConfig: vi.fn(async (): Promise<{ x_eve_yaml?: string | null } | null> => null),
  manifest: vi.fn(async (): Promise<{ manifest_yaml: string; parsed_defaults?: unknown } | null> => null),
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: mocks.decide,
  executionLogQueries: vi.fn(() => ({ appendLog: mocks.appendLog })),
  agentConfigQueries: vi.fn(() => ({ findLatestByProject: mocks.agentConfig })),
  projectManifestQueries: vi.fn(() => ({ findLatestByProject: mocks.manifest })),
}));

import { LoopService } from './loop.service';

type Routing = { harnessSpec: string; profileHash: string | null; profileSource: string | null };
type Select = (job: Record<string, unknown>, attempt: Record<string, unknown>, executionType: string) => Promise<Routing>;

const PROVIDER_ENV = ['Z_AI_API_KEY', 'ZAI_API_KEY', 'GOOGLE_API_KEY', 'GEMINI_API_KEY'];
const savedEnv: Record<string, string | undefined> = {};

function loop(options: {
  projectPreference?: string[];
  systemPreference?: string[];
  secrets?: Record<string, string>;
  userSecrets?: Record<string, string>;
} = {}) {
  const instance = Object.create(LoopService.prototype) as Record<string, unknown>;
  instance.db = (() => []) as never;
  instance.logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
  instance.agentRuntimeConfigured = true;
  instance.getManifestDefaults = vi.fn(async () =>
    options.projectPreference ? { harness_preference: options.projectPreference } : null);
  instance.getSystemHarnessPreference = vi.fn(async () => options.systemPreference);
  const resolveSecrets = vi.fn(async (_projectId: string, userId?: string) =>
    userId ? { ...(options.secrets ?? {}), ...(options.userSecrets ?? {}) } : { ...(options.secrets ?? {}) });
  instance.resolveSecretsForHarnessSelection = resolveSecrets;
  const select = (instance as unknown as { selectHarnessAndRoute: Select }).selectHarnessAndRoute.bind(instance);
  return { select, resolveSecrets };
}

function job(overrides: Record<string, unknown> = {}) {
  return {
    id: 'tracker-a1b2c3d4', project_id: 'proj_trg', harness: null, harness_profile: null,
    harness_profile_source: null, harness_options: null, hints: {}, actor_user_id: 'user_alice',
    user_secrets_excluded: false, ...overrides,
  };
}

const attempt = { id: 'att_1', agent_id: 'triage', harness: null };

function rulesDecided(): string[] {
  return mocks.decide.mock.calls.map((call) => call[1] as string);
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profile = 'legacy';
  mocks.decide.mockImplementation(async () => mocks.profile);
  mocks.agentConfig.mockResolvedValue(null);
  mocks.manifest.mockResolvedValue(null);
  for (const key of PROVIDER_ENV) {
    savedEnv[key] = process.env[key];
    delete process.env[key];
  }
});

afterEach(() => {
  for (const key of PROVIDER_ENV) {
    if (savedEnv[key] === undefined) delete process.env[key];
    else process.env[key] = savedEnv[key];
  }
});

describe('harness selection with nothing configured', () => {
  it('fails under strict instead of using the built-in list', async () => {
    mocks.profile = 'strict';
    const { select } = loop({ secrets: { Z_AI_API_KEY: 'zk' } });

    await expect(select(job(), attempt, 'agent')).rejects.toThrow(/no harness configured/i);
    expect(rulesDecided()).toEqual(['harness.no_preference']);
  });

  it('uses the built-in list under audit and records a finding', async () => {
    mocks.profile = 'audit';
    const { select } = loop({ secrets: { Z_AI_API_KEY: 'zk' } });

    const routing = await select(job(), attempt, 'agent');

    expect(routing.harnessSpec).toBe('zai');
    expect(rulesDecided()).toEqual(['harness.no_preference']);
    expect(mocks.decide).toHaveBeenCalledWith(expect.anything(), 'harness.no_preference', expect.objectContaining({
      projectId: 'proj_trg',
      governing: 'project',
    }));
  });

  it('decides nothing when the project or instance names a preference', async () => {
    mocks.profile = 'strict';
    const project = await loop({ projectPreference: ['zai'], secrets: { Z_AI_API_KEY: 'zk' } }).select(job(), attempt, 'agent');
    const instance = await loop({ systemPreference: ['zai'], secrets: { Z_AI_API_KEY: 'zk' } }).select(job(), attempt, 'agent');

    expect(project.harnessSpec).toBe('zai');
    expect(instance.harnessSpec).toBe('zai');
    expect(mocks.decide).not.toHaveBeenCalled();
  });
});

describe('an explicit harness with no credential', () => {
  it('fails at dispatch under strict', async () => {
    mocks.profile = 'strict';
    const { select } = loop({ secrets: {} });

    await expect(select(job({ harness: 'gemini' }), attempt, 'agent')).rejects.toThrow(/gemini.*credential/i);
    expect(rulesDecided()).toEqual(['harness.missing_credential']);
  });

  it("counts the job actor's own provider key", async () => {
    mocks.profile = 'strict';
    const { select, resolveSecrets } = loop({ secrets: {}, userSecrets: { GEMINI_API_KEY: 'gk' } });

    const routing = await select(job({ harness: 'gemini' }), attempt, 'agent');

    expect(routing.harnessSpec).toBe('gemini');
    expect(resolveSecrets).toHaveBeenCalledWith('proj_trg', 'user_alice');
    expect(mocks.decide).not.toHaveBeenCalled();
  });

  it('runs under audit and records a finding', async () => {
    mocks.profile = 'audit';
    const { select } = loop({ secrets: {} });

    const routing = await select(job({ harness: 'gemini' }), attempt, 'agent');

    expect(routing.harnessSpec).toBe('gemini');
    expect(rulesDecided()).toEqual(['harness.missing_credential']);
  });
});

describe('a named profile at dispatch', () => {
  const manifestWithProfile = {
    manifest_yaml: 'x-eve:\n  agents:\n    profiles:\n      triage:\n        - harness: zai\n          model: glm-4.6\n',
  };

  it('fails under strict when the profile does not exist', async () => {
    mocks.profile = 'strict';
    mocks.manifest.mockResolvedValue({ manifest_yaml: 'x-eve:\n  agents:\n    profiles: {}\n' });
    const { select } = loop({ projectPreference: ['zai'], secrets: { Z_AI_API_KEY: 'zk' } });

    await expect(select(job({ harness_profile: 'triage', harness_profile_source: 'string_ref' }), attempt, 'agent'))
      .rejects.toThrow(/harness profile "triage"/);
    expect(rulesDecided()).toEqual(['harness.missing_profile']);
  });

  it('fails under strict when the profiles cannot be read', async () => {
    mocks.profile = 'strict';
    mocks.agentConfig.mockRejectedValue(new Error('connection reset'));
    const { select } = loop({ projectPreference: ['zai'], secrets: { Z_AI_API_KEY: 'zk' } });

    await expect(select(job({ harness_profile: 'triage', harness_profile_source: 'agent_default' }), attempt, 'agent'))
      .rejects.toThrow(/harness profile "triage"/);
    expect(rulesDecided()).toEqual(['harness.missing_profile']);
  });

  it('runs under audit and records a finding', async () => {
    mocks.profile = 'audit';
    const { select } = loop({ projectPreference: ['zai'], secrets: { Z_AI_API_KEY: 'zk' } });

    const routing = await select(job({ harness_profile: 'triage', harness_profile_source: 'string_ref' }), attempt, 'agent');

    expect(routing.harnessSpec).toBe('zai');
    expect(rulesDecided()).toEqual(['harness.missing_profile']);
  });

  it('decides nothing when the profile exists', async () => {
    mocks.profile = 'strict';
    mocks.manifest.mockResolvedValue(manifestWithProfile);
    const { select } = loop({ secrets: { Z_AI_API_KEY: 'zk' } });

    const routing = await select(
      job({ harness: 'zai', harness_profile: 'triage', harness_profile_source: 'string_ref' }), attempt, 'agent',
    );

    expect(routing.harnessSpec).toBe('zai');
    expect(mocks.decide).not.toHaveBeenCalled();
  });

  it('ignores the named profile when an inline override chose the harness', async () => {
    mocks.profile = 'strict';
    const { select } = loop({ secrets: { Z_AI_API_KEY: 'zk' } });

    const routing = await select(
      job({ harness: 'zai', harness_profile: 'triage', harness_profile_source: 'workflow_template' }), attempt, 'agent',
    );

    expect(routing.harnessSpec).toBe('zai');
    expect(mocks.decide).not.toHaveBeenCalled();
  });
});
