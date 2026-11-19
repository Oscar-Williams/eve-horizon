import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SecurityProfile } from '@eve/shared';
import { SecretsService } from './secrets.service';
import type { SecurityService } from '../security/security.service';

// The resolve the worker sends to a runner pod: a job's bound secrets, for the
// actor its token was minted for, with the clone credential flagged
// clone_only. Under strict an unbound job receives only its harness
// credential and the keys its env overrides reference.

const state = vi.hoisted(() => ({
  byScope: {} as Record<string, Array<{ key: string; value_encrypted: string; type: string }>>,
  userScopeIds: [] as string[],
  jobs: {} as Record<string, Record<string, unknown>>,
  agents: {} as Record<string, Record<string, unknown>>,
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    secretQueries: vi.fn(() => ({
      listByScope: vi.fn(async (scopeType: string, scopeId: string) => {
        if (scopeType === 'user') state.userScopeIds.push(scopeId);
        return scopeType === 'user' ? (state.byScope[`user:${scopeId}`] ?? []) : (state.byScope[scopeType] ?? []);
      }),
    })),
    projectQueries: vi.fn(() => ({
      findById: vi.fn(async () => ({ id: 'proj_shop', org_id: 'org_acme', repo_url: 'https://github.com/acme/shop.git' })),
    })),
    orgQueries: vi.fn(() => ({ findById: vi.fn(async () => ({ id: 'org_acme', slug: 'acme' })) })),
    systemSettingsQueries: vi.fn(() => ({ get: vi.fn(async () => null) })),
    jobQueries: vi.fn(() => ({ findById: vi.fn(async (id: string) => state.jobs[id] ?? null) })),
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
  const decide = vi.fn(async (rule: string, _ctx?: { detail?: unknown }) => profiles[rule] ?? 'legacy');
  const secrets = new SecretsService({} as never, { decide } as unknown as SecurityService);
  (secrets as unknown as { decrypt: (v: string) => string }).decrypt = (v) => v;
  return { secrets, decide };
}

function summary(items: Array<{ key: string; value: string; clone_only?: boolean }>) {
  return Object.fromEntries(items.map((item) => [item.key, item.clone_only ? `${item.value} (clone only)` : item.value]));
}

beforeEach(() => {
  state.userScopeIds = [];
  state.byScope = {
    system: [],
    org: [env('ANTHROPIC_API_KEY', 'sk-org'), env('MAPS_KEY', 'maps-org')],
    project: [
      env('GITHUB_TOKEN', 'ghp_shop', 'github_token'),
      env('APP_DB_URL', 'postgres://app'),
      env('STRIPE_KEY', 'sk_live_shop'),
    ],
    'user:user_alice': [env('ALICE_NOTES_KEY', 'alice-1')],
    'user:user_mallory': [env('MALLORY_KEY', 'mallory-1')],
  };
  state.jobs = {
    job_bound: {
      id: 'job_bound', project_id: 'proj_shop', assignee: 'agent_review', target: null,
      secrets_allowlist: null, env_overrides: null, actor_user_id: 'user_alice',
    },
    job_unbound: {
      id: 'job_unbound', project_id: 'proj_shop', assignee: null, target: null, secrets_allowlist: null,
      env_overrides: { DATABASE_URL: '${secret.APP_DB_URL}' }, actor_user_id: 'user_alice',
    },
  };
  state.agents = { agent_review: { id: 'agent_review', slug: 'review', access_json: { secrets: ['ANTHROPIC_API_KEY'] } } };
});

describe('a job resolve for a runner pod', () => {
  it('returns the bound keys and the clone credential flagged clone_only, and nothing else', async () => {
    const { secrets } = service({});

    const resolved = await secrets.resolveForJob('proj_shop', 'job_bound', 'claude');

    expect(summary(resolved)).toEqual({ ANTHROPIC_API_KEY: 'sk-org', GITHUB_TOKEN: 'ghp_shop (clone only)' });
  });

  it('withholds everything else from an unbound job under strict', async () => {
    const { secrets, decide } = service({ 'secrets.unbound_job': 'strict' });

    const resolved = await secrets.resolveForJob('proj_shop', 'job_unbound', 'claude');

    expect(summary(resolved)).toEqual({
      ANTHROPIC_API_KEY: 'sk-org',
      APP_DB_URL: 'postgres://app',
      GITHUB_TOKEN: 'ghp_shop (clone only)',
    });
    expect(decide.mock.calls.filter(([rule]) => rule === 'secrets.unbound_job').map(([, ctx]) => ctx?.detail))
      .toEqual([expect.objectContaining({ withheld: 'ALICE_NOTES_KEY,MAPS_KEY,STRIPE_KEY', bound_resolve: true })]);
  });

  it('delivers every secret to an unbound job under audit, the clone credential included as its own', async () => {
    const { secrets, decide } = service({ 'secrets.unbound_job': 'audit' });

    const resolved = await secrets.resolveForJob('proj_shop', 'job_unbound', 'claude');

    expect(summary(resolved)).toEqual({
      ANTHROPIC_API_KEY: 'sk-org', MAPS_KEY: 'maps-org', GITHUB_TOKEN: 'ghp_shop', APP_DB_URL: 'postgres://app',
      STRIPE_KEY: 'sk_live_shop', ALICE_NOTES_KEY: 'alice-1',
    });
    expect(decide.mock.calls.filter(([rule]) => rule === 'secrets.unbound_job').map(([, ctx]) => ctx?.detail))
      .toEqual([expect.objectContaining({ withheld: 'ALICE_NOTES_KEY,MAPS_KEY,STRIPE_KEY', bound_resolve: true })]);
  });

  it("resolves user secrets for the job's own actor only", async () => {
    const { secrets } = service({});

    await secrets.resolveForJob('proj_shop', 'job_unbound', 'claude');
    expect(state.userScopeIds).toEqual(['user_alice']);

    state.userScopeIds = [];
    state.jobs.job_unbound.user_secrets_excluded = true;
    const excluded = await secrets.resolveForJob('proj_shop', 'job_unbound', 'claude');
    expect(state.userScopeIds).toEqual([]);
    expect(Object.keys(summary(excluded))).not.toContain('ALICE_NOTES_KEY');
  });

  it('refuses a job of another project', async () => {
    state.jobs.job_other = { ...state.jobs.job_unbound, id: 'job_other', project_id: 'proj_other' };
    const { secrets } = service({});
    await expect(secrets.resolveForJob('proj_shop', 'job_other', 'claude')).rejects.toThrow(/not found/i);
  });
});
