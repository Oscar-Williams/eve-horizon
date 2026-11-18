import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SecurityProfile } from '@eve/shared';
import { SecretsService } from './secrets.service';
import type { SecurityService } from '../security/security.service';

// Rows per scope; values are stored as plain text and `decrypt` is the identity.
const rows = vi.hoisted(() => ({
  byScope: {} as Record<string, Array<{ key: string; value_encrypted: string; type: string }>>,
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    secretQueries: vi.fn(() => ({
      listByScope: vi.fn(async (scopeType: string) => rows.byScope[scopeType] ?? []),
    })),
    projectQueries: vi.fn(() => ({ findById: vi.fn(async () => ({ id: 'proj_a', org_id: 'org_a' })) })),
  };
});

function env(key: string, value: string) {
  return { key, value_encrypted: value, type: 'env_var' };
}

function service(profile: SecurityProfile) {
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  process.env.EVE_SECRETS_MASTER_KEY = 'test-master-key';
  const decide = vi.fn(async () => profile);
  const secrets = new SecretsService({} as never, { decide } as unknown as SecurityService);
  (secrets as unknown as { decrypt: (v: string) => string }).decrypt = (v) => v;
  return { secrets, decide };
}

function byKey(resolved: Array<{ key: string; value: string; scope_type: string }>) {
  return Object.fromEntries(resolved.map((r) => [r.key, `${r.scope_type}:${r.value}`]));
}

beforeEach(() => {
  rows.byScope = {
    system: [],
    org: [env('ANTHROPIC_BASE_URL', 'https://org-gateway.example.test'), env('ANTHROPIC_API_KEY', 'sk-org')],
    user: [
      env('ANTHROPIC_BASE_URL', 'https://elsewhere.example.test'),
      env('https_proxy', 'http://proxy.example.test'),
      env('NODE_OPTIONS', '--require /tmp/x.js'),
      env('LD_PRELOAD', '/tmp/x.so'),
      env('BASH_ENV', '/tmp/x.sh'),
      env('ANTHROPIC_API_KEY', 'sk-user'),
      env('MY_TOOL_TOKEN', 'tok'),
    ],
    project: [],
  };
});

describe('user-scope secrets that route model traffic or load code', () => {
  it('drops them under strict, keeping the user provider key and the org setting underneath', async () => {
    const { secrets, decide } = service('strict');

    const resolved = byKey(await secrets.resolveForProject('proj_a', 'user_1'));

    expect(resolved).toEqual({
      ANTHROPIC_BASE_URL: 'org:https://org-gateway.example.test',
      ANTHROPIC_API_KEY: 'user:sk-user',
      MY_TOOL_TOKEN: 'user:tok',
    });
    expect(decide).toHaveBeenCalledWith('harness.user_secret_routing', expect.objectContaining({
      projectId: 'proj_a',
      governing: 'project',
      detail: expect.objectContaining({ secrets: 'ANTHROPIC_BASE_URL,BASH_ENV,LD_PRELOAD,NODE_OPTIONS,https_proxy' }),
    }));
  });

  it('keeps them under audit and records a finding', async () => {
    const { secrets, decide } = service('audit');

    const resolved = byKey(await secrets.resolveForProject('proj_a', 'user_1'));

    expect(resolved.ANTHROPIC_BASE_URL).toBe('user:https://elsewhere.example.test');
    expect(resolved.NODE_OPTIONS).toBe('user:--require /tmp/x.js');
    expect(decide).toHaveBeenCalledTimes(1);
    expect(decide).toHaveBeenCalledWith('harness.user_secret_routing', expect.anything());
  });

  it('decides nothing when the user holds none of them', async () => {
    rows.byScope.user = [env('ANTHROPIC_API_KEY', 'sk-user')];
    const { secrets, decide } = service('strict');

    const resolved = byKey(await secrets.resolveForProject('proj_a', 'user_1'));

    expect(resolved.ANTHROPIC_API_KEY).toBe('user:sk-user');
    expect(decide).not.toHaveBeenCalled();
  });

  it('leaves project and org secrets of the same names alone', async () => {
    rows.byScope.user = [];
    rows.byScope.project = [env('NODE_OPTIONS', '--max-old-space-size=4096')];
    const { secrets, decide } = service('strict');

    const resolved = byKey(await secrets.resolveForProject('proj_a', 'user_1'));

    expect(resolved.NODE_OPTIONS).toBe('project:--max-old-space-size=4096');
    expect(resolved.ANTHROPIC_BASE_URL).toBe('org:https://org-gateway.example.test');
    expect(decide).not.toHaveBeenCalled();
  });
});
