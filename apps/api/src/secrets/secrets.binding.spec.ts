import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SecurityProfile } from '@eve/shared';
import { SecretsService } from './secrets.service';
import type { SecurityService } from '../security/security.service';

// Rules secrets.system_scope and secrets.unbound_job at the resolve that
// delivers a project's secrets to its workloads and jobs.

const state = vi.hoisted(() => ({
  byScope: {} as Record<string, Array<{ key: string; value_encrypted: string; type: string }>>,
  settings: {} as Record<string, string>,
  jobs: {} as Record<string, Record<string, unknown>>,
  agents: {} as Record<string, Record<string, unknown>>,
  repoUrl: 'https://github.com/acme/shop.git',
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    secretQueries: vi.fn(() => ({
      listByScope: vi.fn(async (scopeType: string) => state.byScope[scopeType] ?? []),
    })),
    projectQueries: vi.fn(() => ({
      findById: vi.fn(async () => ({ id: 'proj_shop', org_id: 'org_acme', repo_url: state.repoUrl })),
    })),
    orgQueries: vi.fn(() => ({ findById: vi.fn(async () => ({ id: 'org_acme', slug: 'acme' })) })),
    systemSettingsQueries: vi.fn(() => ({
      get: vi.fn(async (key: string) => (key in state.settings ? { key, value: state.settings[key] } : null)),
    })),
    jobQueries: vi.fn(() => ({
      findById: vi.fn(async (id: string) => state.jobs[id] ?? null),
    })),
    agentQueries: vi.fn(() => ({
      findByProjectAndId: vi.fn(async (_project: string, id: string) => state.agents[id] ?? null),
      findByOrgAndSlug: vi.fn(async () => null),
    })),
  };
});

function env(key: string, value: string, type = 'env_var') {
  return { key, value_encrypted: value, type };
}

function service(profiles: Record<string, SecurityProfile>) {
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  process.env.EVE_SECRETS_MASTER_KEY = 'test-master-key';
  const decide = vi.fn(async (rule: string) => profiles[rule] ?? 'legacy');
  const secrets = new SecretsService({} as never, { decide } as unknown as SecurityService);
  (secrets as unknown as { decrypt: (v: string) => string }).decrypt = (v) => v;
  return { secrets, decide };
}

function byKey(resolved: Array<{ key: string; value: string; scope_type: string }>) {
  return Object.fromEntries(resolved.map((r) => [r.key, `${r.scope_type}:${r.value}`]));
}

function decisions(decide: ReturnType<typeof vi.fn>, rule: string) {
  return decide.mock.calls.filter((call) => call[0] === rule).map((call) => call[1]);
}

beforeEach(() => {
  state.byScope = {
    system: [env('SHARED_TOOL_KEY', 'tool-1'), env('OPENAI_API_KEY', 'sk-system'), env('MAPS_KEY', 'maps-system')],
    org: [env('ANTHROPIC_API_KEY', 'sk-org'), env('MAPS_KEY', 'maps-org')],
    user: [],
    project: [],
  };
  state.settings = { 'secrets.system_shared_keys': 'SHARED_TOOL_KEY, OTHER_KEY' };
  state.jobs = {};
  state.agents = {};
  state.repoUrl = 'https://github.com/acme/shop.git';
});

describe('secrets.system_scope', () => {
  it('withholds system secrets the instance does not share by name under strict', async () => {
    const { secrets, decide } = service({ 'secrets.system_scope': 'strict' });

    const resolved = byKey(await secrets.resolveForProject('proj_shop'));

    expect(resolved).toEqual({
      SHARED_TOOL_KEY: 'system:tool-1',
      ANTHROPIC_API_KEY: 'org:sk-org',
      MAPS_KEY: 'org:maps-org',
    });
    expect(decisions(decide, 'secrets.system_scope')).toEqual([expect.objectContaining({
      projectId: 'proj_shop',
      governing: 'project',
      detail: expect.objectContaining({ keys: 'OPENAI_API_KEY' }),
    })]);
  });

  it('delivers them under audit and records each key delivered', async () => {
    const { secrets, decide } = service({ 'secrets.system_scope': 'audit' });

    const resolved = byKey(await secrets.resolveForProject('proj_shop'));

    expect(resolved.OPENAI_API_KEY).toBe('system:sk-system');
    expect(resolved.SHARED_TOOL_KEY).toBe('system:tool-1');
    expect(decisions(decide, 'secrets.system_scope')).toEqual([
      expect.objectContaining({ detail: expect.objectContaining({ keys: 'OPENAI_API_KEY' }) }),
    ]);
  });

  it('withholds every system secret under strict when the instance shares none', async () => {
    state.settings = {};
    const { secrets } = service({ 'secrets.system_scope': 'strict' });

    const resolved = byKey(await secrets.resolveForProject('proj_shop'));

    expect(Object.keys(resolved).sort()).toEqual(['ANTHROPIC_API_KEY', 'MAPS_KEY']);
  });

  it('decides nothing when only shared system secrets reach the project', async () => {
    state.byScope.system = [env('SHARED_TOOL_KEY', 'tool-1')];
    const { secrets, decide } = service({ 'secrets.system_scope': 'strict' });

    const resolved = byKey(await secrets.resolveForProject('proj_shop'));

    expect(resolved.SHARED_TOOL_KEY).toBe('system:tool-1');
    expect(decisions(decide, 'secrets.system_scope')).toEqual([]);
  });

  it('applies to the org-level resolve too', async () => {
    const { secrets } = service({ 'secrets.system_scope': 'strict' });

    const resolved = Object.fromEntries((await secrets.resolveForOrg('org_acme')).map((s) => [s.key, s.value]));

    expect(resolved).toEqual({ SHARED_TOOL_KEY: 'tool-1', ANTHROPIC_API_KEY: 'sk-org', MAPS_KEY: 'maps-org' });
  });
});

describe('secrets.unbound_job', () => {
  beforeEach(() => {
    state.byScope.system = [];
    state.byScope.project = [
      env('GITHUB_TOKEN', 'ghp_shop', 'github_token'),
      env('APP_DB_URL', 'postgres://app'),
      env('STRIPE_KEY', 'sk_live_shop'),
      env('OPENAI_API_KEY', 'sk-openai'),
    ];
    state.jobs.job_unbound = {
      id: 'job_unbound',
      project_id: 'proj_shop',
      assignee: null,
      target: null,
      secrets_allowlist: null,
      env_overrides: { DATABASE_URL: '${secret.APP_DB_URL}' },
      actor_user_id: 'user_alice',
    };
  });

  it('records a job with no binding, naming what strict would withhold', async () => {
    const { secrets, decide } = service({ 'secrets.unbound_job': 'audit' });

    const resolved = byKey(await secrets.resolveForProject('proj_shop', undefined, { jobId: 'job_unbound', harness: 'claude' }));

    // Under audit the job still receives everything.
    expect(Object.keys(resolved).sort()).toEqual([
      'ANTHROPIC_API_KEY', 'APP_DB_URL', 'GITHUB_TOKEN', 'MAPS_KEY', 'OPENAI_API_KEY', 'STRIPE_KEY',
    ]);
    // Kept under strict: the harness credential, the keys its env overrides
    // reference, and the clone credential (clone-only, never the job's).
    expect(decisions(decide, 'secrets.unbound_job')).toEqual([expect.objectContaining({
      projectId: 'proj_shop',
      governing: 'project',
      actor: expect.objectContaining({ is_job_token: true, job_id: 'job_unbound' }),
      detail: expect.objectContaining({
        job_id: 'job_unbound',
        harness: 'claude',
        withheld: 'MAPS_KEY,OPENAI_API_KEY,STRIPE_KEY',
        withheld_count: 3,
      }),
    })]);
  });

  it('records nothing for a job bound by its own allowlist', async () => {
    state.jobs.job_unbound.secrets_allowlist = ['ANTHROPIC_API_KEY'];
    const { secrets, decide } = service({ 'secrets.unbound_job': 'audit' });

    await secrets.resolveForProject('proj_shop', undefined, { jobId: 'job_unbound', harness: 'claude' });

    expect(decisions(decide, 'secrets.unbound_job')).toEqual([]);
  });

  it('records nothing for a job whose agent declares access.secrets', async () => {
    state.jobs.job_unbound.assignee = 'agent_review';
    state.agents.agent_review = { id: 'agent_review', slug: 'review', access_json: { secrets: ['ANTHROPIC_API_KEY'] } };
    const { secrets, decide } = service({ 'secrets.unbound_job': 'audit' });

    await secrets.resolveForProject('proj_shop', undefined, { jobId: 'job_unbound', harness: 'claude' });

    expect(decisions(decide, 'secrets.unbound_job')).toEqual([]);
  });

  it('keeps only the selected harness credential', async () => {
    const { secrets, decide } = service({ 'secrets.unbound_job': 'audit' });

    await secrets.resolveForProject('proj_shop', undefined, { jobId: 'job_unbound', harness: 'codex' });

    expect(decisions(decide, 'secrets.unbound_job')[0].detail).toEqual(expect.objectContaining({
      harness: 'codex',
      withheld: 'ANTHROPIC_API_KEY,MAPS_KEY,STRIPE_KEY',
    }));
  });

  it('treats a git token as the clone credential only for a repository it authenticates', async () => {
    state.byScope.project[0] = env('GITHUB_TOKEN', 'ghp_shop', 'env_var');
    state.repoUrl = 'https://git.example.com/acme/shop.git';
    const { secrets, decide } = service({ 'secrets.unbound_job': 'audit' });

    await secrets.resolveForProject('proj_shop', undefined, { jobId: 'job_unbound', harness: 'claude' });

    expect(decisions(decide, 'secrets.unbound_job')[0].detail).toEqual(expect.objectContaining({
      withheld: 'GITHUB_TOKEN,MAPS_KEY,OPENAI_API_KEY,STRIPE_KEY',
    }));
  });

  it('ignores a job of another project', async () => {
    state.jobs.job_other = { ...state.jobs.job_unbound, id: 'job_other', project_id: 'proj_other' };
    const { secrets, decide } = service({ 'secrets.unbound_job': 'audit' });

    await secrets.resolveForProject('proj_shop', undefined, { jobId: 'job_other', harness: 'claude' });

    expect(decisions(decide, 'secrets.unbound_job')).toEqual([]);
  });

  it('decides nothing for a resolve that names no job', async () => {
    const { secrets, decide } = service({ 'secrets.unbound_job': 'audit' });

    await secrets.resolveForProject('proj_shop');

    expect(decisions(decide, 'secrets.unbound_job')).toEqual([]);
  });
});
