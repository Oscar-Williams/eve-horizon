import { BadRequestException, ConflictException, ForbiddenException } from '@nestjs/common';
import { afterAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { IntegrationsService } from './integrations.service';
import { SlackOAuthController } from './slack-oauth.controller';
import { GoogleDriveOAuthController } from '../cloud-fs/google-drive-oauth.controller';
import type { AuthUser } from '../auth/auth.types';

process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
process.env.EVE_SECRETS_MASTER_KEY = 'test-master-key';
process.env.EVE_INTERNAL_API_KEY = 'test-internal-key';
process.env.EVE_API_URL = 'https://api.eve.example';

type StateRow = {
  id: string; provider: string; org_id: string; user_id: string | null; install_binding: string | null;
  code: string | null; expires_at: Date; created_at: Date;
};

/** OAuth states, integrations and app configs, shared by every service built here (as one database is). */
const store = vi.hoisted(() => ({
  states: [] as StateRow[],
  integrations: [] as Array<Record<string, unknown> & { id: string; provider: string; account_id: string }>,
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const live = (row: StateRow) => row.expires_at.getTime() > Date.now();
  const take = (match: (row: StateRow) => boolean) => {
    const row = store.states.find(match);
    if (!row) return undefined;
    store.states = store.states.filter((r) => r !== row);
    return row;
  };
  return {
    ...actual,
    oauthStateQueries: vi.fn(() => ({
      create: vi.fn(async (row: Omit<StateRow, 'code' | 'created_at'>) => {
        store.states.push({ ...row, code: null, created_at: new Date() });
      }),
      find: vi.fn(async (id: string) => store.states.find((r) => r.id === id)),
      recordCode: vi.fn(async (id: string, code: string) => {
        const row = store.states.find((r) => r.id === id && r.code === null && live(r));
        if (!row) return false;
        row.code = code;
        return true;
      }),
      consumeForUser: vi.fn(async (id: string, userId: string) =>
        take((r) => r.id === id && r.user_id === userId && r.code !== null && live(r))),
      consumeForInstall: vi.fn(async (id: string, binding: string) =>
        take((r) => r.id === id && r.install_binding === binding && live(r))),
      deleteExpired: vi.fn(async () => {
        store.states = store.states.filter(live);
      }),
    })),
    oauthAppConfigQueries: vi.fn(() => ({
      findByOrgAndProvider: vi.fn(async (orgId: string, provider: string) => ({
        id: `oac_${provider}`, org_id: orgId, provider, client_id: `client-${provider}`,
        client_secret: `secret-${provider}`, config_json: {}, label: null, status: 'active', created_by: null,
        created_at: new Date(), updated_at: new Date(),
      })),
    })),
    integrationQueries: vi.fn(() => ({
      findByProviderAccount: vi.fn(async (provider: string, account: string) =>
        store.integrations.find((r) => r.provider === provider && r.account_id === account)),
      insert: vi.fn(async (row: Record<string, unknown> & { id: string; provider: string; account_id: string }) => {
        const created = { ...row, created_at: new Date(), updated_at: new Date() };
        store.integrations.push(created);
        return created;
      }),
      updateTokens: vi.fn(async (id: string) => store.integrations.find((r) => r.id === id)),
    })),
    systemSettingsQueries: vi.fn(() => ({ get: vi.fn(async () => null) })),
  };
});

const ORG = 'org_acme';
const alice = { user_id: 'user_alice' } as AuthUser;
const originalFetch = globalThis.fetch;
let fetchMock: ReturnType<typeof vi.fn>;

function slackTokenResponse() {
  return {
    ok: true,
    json: async () => ({
      ok: true,
      team: { id: 'T_ACME', name: 'Acme' },
      access_token: 'xoxb-acme',
      bot_user_id: 'U_BOT',
    }),
  };
}

function service() {
  return new IntegrationsService({} as never);
}

function stateOf(url: string): string {
  const state = new URL(url).searchParams.get('state');
  if (!state) throw new Error(`no state in ${url}`);
  return state;
}

function cookieValue(setCookie: string): string {
  return setCookie.split(';')[0].split('=').slice(1).join('=');
}

beforeEach(() => {
  store.states = [];
  store.integrations = [];
  fetchMock = vi.fn(async () => slackTokenResponse());
  globalThis.fetch = fetchMock as never;
});

afterAll(() => {
  globalThis.fetch = originalFetch;
});

describe('OAuth state bound to the user who started it', () => {
  it('stores the code at the public callback and exchanges nothing', async () => {
    const slack = new SlackOAuthController(service());
    const state = stateOf((await slack.authorize(ORG, alice)).url);

    const result = await slack.callback('code-1', state, undefined, { headers: {} } as never);

    expect(result).toMatchObject({ ok: true, pending: true });
    expect(fetchMock).not.toHaveBeenCalled();
    expect(store.integrations).toHaveLength(0);
  });

  it('completes for the user who started it, with their own token', async () => {
    const slack = new SlackOAuthController(service());
    const state = stateOf((await slack.authorize(ORG, alice)).url);
    await slack.callback('code-1', state, undefined, { headers: {} } as never);

    const done = await service().completeOAuth('slack', state, alice.user_id);

    expect(done).toMatchObject({ ok: true, provider: 'slack', account_id: 'T_ACME' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const body = String((fetchMock.mock.calls[0][1] as { body: URLSearchParams }).body);
    expect(body).toContain('code=code-1');
    expect(body).toContain('client_secret=secret-slack');
    expect(store.integrations).toHaveLength(1);
  });

  it('refuses completion by another user with 403, and leaves the state to its owner', async () => {
    const slack = new SlackOAuthController(service());
    const state = stateOf((await slack.authorize(ORG, alice)).url);
    await slack.callback('code-1', state, undefined, { headers: {} } as never);

    await expect(service().completeOAuth('slack', state, 'user_bob')).rejects.toBeInstanceOf(ForbiddenException);
    expect(fetchMock).not.toHaveBeenCalled();

    await expect(service().completeOAuth('slack', state, alice.user_id)).resolves.toMatchObject({ ok: true });
  });

  it('answers 409 until the browser has come back with a code', async () => {
    const slack = new SlackOAuthController(service());
    const state = stateOf((await slack.authorize(ORG, alice)).url);
    await expect(service().completeOAuth('slack', state, alice.user_id)).rejects.toBeInstanceOf(ConflictException);
  });

  it('accepts a state once, for its own provider, until it expires', async () => {
    const svc = service();
    const slack = new SlackOAuthController(svc);
    const used = stateOf((await slack.authorize(ORG, alice)).url);
    await slack.callback('code-1', used, undefined, { headers: {} } as never);
    await svc.completeOAuth('slack', used, alice.user_id);
    await expect(svc.completeOAuth('slack', used, alice.user_id)).rejects.toBeInstanceOf(BadRequestException);

    const drive = new GoogleDriveOAuthController(svc);
    const driveState = stateOf((await drive.authorize(ORG, alice)).url);
    await expect(slack.callback('code-2', driveState, undefined, { headers: {} } as never))
      .rejects.toBeInstanceOf(BadRequestException);

    const stale = stateOf((await slack.authorize(ORG, alice)).url);
    store.states.forEach((row) => { row.expires_at = new Date(Date.now() - 1000); });
    await expect(slack.callback('code-3', stale, undefined, { headers: {} } as never))
      .rejects.toBeInstanceOf(BadRequestException);
  });

  it('keeps the state in the database, so another replica finishes what one started', async () => {
    const started = new SlackOAuthController(service());
    const state = stateOf((await started.authorize(ORG, alice)).url);
    const other = new SlackOAuthController(service());
    await expect(other.callback('code-1', state, undefined, { headers: {} } as never))
      .resolves.toMatchObject({ pending: true });
    expect(store.states[0].id).not.toBe(state);
  });

  it('stores the Google Drive code at its callback too, for the user to complete', async () => {
    const drive = new GoogleDriveOAuthController(service());
    const state = stateOf((await drive.authorize(ORG, alice)).url);

    await expect(drive.callback('code-g', state, undefined)).resolves.toMatchObject({ pending: true });
    expect(fetchMock).not.toHaveBeenCalled();
    await expect(service().completeOAuth('google-drive', state, 'user_bob')).rejects.toBeInstanceOf(ForbiddenException);
  });
});

describe('signed-link Slack install bound to the browser that started it', () => {
  async function startInstall() {
    const svc = service();
    const slack = new SlackOAuthController(svc);
    const { token } = svc.generateSlackInstallToken(ORG);
    const reply = { header: vi.fn() };
    const { url } = await slack.install(token, reply as never);
    const setCookie = reply.header.mock.calls.find(([name]) => String(name).toLowerCase() === 'set-cookie')?.[1] as string;
    return { slack, state: stateOf(url), setCookie };
  }

  it('sets a __Host- cookie that survives the redirect back from Slack', async () => {
    const { setCookie } = await startInstall();
    expect(setCookie).toMatch(/^__Host-[A-Za-z_]+=/);
    expect(setCookie).toContain('Secure');
    expect(setCookie).toContain('HttpOnly');
    expect(setCookie).toContain('SameSite=Lax');
    expect(setCookie).toContain('Path=/');
    expect(setCookie).not.toMatch(/Domain=/i);
  });

  it('completes at the callback only with that cookie', async () => {
    const { slack, state, setCookie } = await startInstall();
    const name = setCookie.split('=')[0];

    await expect(slack.callback('code-1', state, undefined, { headers: {} } as never))
      .rejects.toBeInstanceOf(ForbiddenException);
    await expect(slack.callback('code-1', state, undefined, { headers: { cookie: `${name}=forged` } } as never))
      .rejects.toBeInstanceOf(ForbiddenException);
    expect(fetchMock).not.toHaveBeenCalled();

    const done = await slack.callback('code-1', state, undefined, {
      headers: { cookie: `other=1; ${name}=${cookieValue(setCookie)}` },
    } as never);
    expect(done).toMatchObject({ ok: true, team_id: 'T_ACME' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('cannot be completed through the user route', async () => {
    const { state } = await startInstall();
    await expect(service().completeOAuth('slack', state, alice.user_id)).rejects.toBeInstanceOf(ForbiddenException);
  });
});
