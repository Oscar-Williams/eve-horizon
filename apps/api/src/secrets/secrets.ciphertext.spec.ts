import { ForbiddenException } from '@nestjs/common';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { SecurityProfile } from '@eve/shared';
import { SecretsService, maskSecretValue } from './secrets.service';
import { IntegrationsService } from '../integrations/integrations.service';
import { ProjectGithubController } from '../projects/project-github.controller';
import type { SecurityService } from '../security/security.service';
import type { AuthUser } from '../auth/auth.types';

process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
process.env.EVE_SECRETS_MASTER_KEY = 'test-master-key';

type SecretRow = {
  id: string; scope_type: string; scope_id: string; key: string; type: string;
  value_encrypted: string; created_at: Date; updated_at: Date;
};
type IntegrationRow = {
  id: string; org_id: string; provider: string; account_id: string; tokens_json: unknown;
  settings_json: Record<string, unknown>; status: string; created_at: Date; updated_at: Date;
};
type OAuthConfigRow = {
  id: string; org_id: string; provider: string; client_id: string; client_secret: string;
  config_json: Record<string, unknown>; label: string | null; status: string; created_by: string | null;
  created_at: Date; updated_at: Date;
};

/** In-memory secrets, settings, integrations and OAuth app configs, with compare-and-set swaps. */
const store = vi.hoisted(() => ({
  secrets: [] as SecretRow[],
  settings: new Map<string, string>(),
  integrations: [] as IntegrationRow[],
  oauthConfigs: [] as OAuthConfigRow[],
  /** Runs before each swap: a write from elsewhere between the read and the swap. */
  beforeSwap: null as null | ((id: string) => Promise<void>),
  nextId: 0,
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const now = () => new Date();
  const find = (t: string, id: string, key: string) =>
    store.secrets.find((r) => r.scope_type === t && r.scope_id === id && r.key === key);
  const sealedPattern = /^v2:[A-Za-z0-9+/]{16}:[A-Za-z0-9+/]{22}==:[A-Za-z0-9+/]*={0,2}$/;
  return {
    ...actual,
    secretQueries: vi.fn(() => ({
      create: vi.fn(async (s: Omit<SecretRow, 'created_at' | 'updated_at'>) => {
        const row = { ...s, created_at: now(), updated_at: now() };
        store.secrets.push(row);
        return row;
      }),
      listByScope: vi.fn(async (t: string, id: string) =>
        store.secrets.filter((r) => r.scope_type === t && r.scope_id === id)),
      findByScopeAndKey: vi.fn(async (t: string, id: string, key: string) => find(t, id, key) ?? null),
      updateByKey: vi.fn(async (t: string, id: string, key: string, u: { value_encrypted?: string; type?: string }) => {
        const row = find(t, id, key);
        if (!row) return null;
        if (u.value_encrypted) row.value_encrypted = u.value_encrypted;
        if (u.type) row.type = u.type;
        row.updated_at = now();
        return row;
      }),
      deleteByKey: vi.fn(async (t: string, id: string, key: string) => {
        const before = store.secrets.length;
        store.secrets = store.secrets.filter((r) => !(r.scope_type === t && r.scope_id === id && r.key === key));
        return store.secrets.length < before;
      }),
      countByFormat: vi.fn(async () => {
        const counts: Record<string, number> = {};
        for (const r of store.secrets) {
          const format = r.value_encrypted.split(':')[0];
          counts[format] = (counts[format] ?? 0) + 1;
        }
        return counts;
      }),
      listInFormat: vi.fn(async (format: string, afterId: string, limit: number) =>
        store.secrets
          .filter((r) => r.value_encrypted.startsWith(`${format}:`) && r.id > afterId)
          .sort((a, b) => a.id.localeCompare(b.id))
          .slice(0, limit)
          .map((r) => ({ ...r }))),
      swapCiphertext: vi.fn(async (id: string, from: string, to: string) => {
        await store.beforeSwap?.(id);
        const row = store.secrets.find((r) => r.id === id);
        if (!row || row.value_encrypted !== from) return false;
        row.value_encrypted = to;
        return true;
      }),
    })),
    projectQueries: vi.fn(() => ({
      findById: vi.fn(async (id: string) => ({ id, org_id: 'org_acme', repo_url: 'https://example.com/acme/shop.git' })),
    })),
    orgQueries: vi.fn(() => ({ findById: vi.fn(async (id: string) => ({ id })) })),
    systemSettingsQueries: vi.fn(() => ({
      get: vi.fn(async (key: string) => (store.settings.has(key) ? { key, value: store.settings.get(key) } : null)),
      set: vi.fn(async (key: string, value: string) => {
        store.settings.set(key, value);
        return { key, value };
      }),
    })),
    integrationQueries: vi.fn(() => ({
      findById: vi.fn(async (id: string) => store.integrations.find((r) => r.id === id)),
      findByProviderAccount: vi.fn(async (provider: string, account: string) =>
        store.integrations.find((r) => r.provider === provider && r.account_id === account)),
      listActive: vi.fn(async () => store.integrations.filter((r) => r.status === 'active')),
      listByOrg: vi.fn(async (orgId: string) => store.integrations.filter((r) => r.org_id === orgId)),
      insert: vi.fn(async (row: Omit<IntegrationRow, 'created_at' | 'updated_at'>) => {
        const created = { ...row, created_at: now(), updated_at: now() };
        store.integrations.push(created);
        return created;
      }),
      updateTokens: vi.fn(async (id: string, tokens: unknown, status?: string) => {
        const row = store.integrations.find((r) => r.id === id);
        if (!row) return undefined;
        row.tokens_json = tokens;
        if (status) row.status = status;
        return row;
      }),
      countTokenFormats: vi.fn(async () => ({
        plain: store.integrations.filter((r) => r.tokens_json && typeof r.tokens_json === 'object').length,
        sealed: store.integrations.filter((r) => typeof r.tokens_json === 'string').length,
      })),
      listPlainTokens: vi.fn(async (afterId: string, limit: number) =>
        store.integrations
          .filter((r) => r.tokens_json && typeof r.tokens_json === 'object' && r.id > afterId)
          .sort((a, b) => a.id.localeCompare(b.id))
          .slice(0, limit)
          .map((r) => ({ id: r.id, tokens_json: r.tokens_json as Record<string, unknown> }))),
      swapTokens: vi.fn(async (id: string, from: Record<string, unknown>, to: string) => {
        await store.beforeSwap?.(id);
        const row = store.integrations.find((r) => r.id === id);
        if (!row || JSON.stringify(row.tokens_json) !== JSON.stringify(from)) return false;
        row.tokens_json = to;
        return true;
      }),
    })),
    oauthAppConfigQueries: vi.fn(() => ({
      findByOrgAndProvider: vi.fn(async (orgId: string, provider: string) =>
        store.oauthConfigs.find((r) => r.org_id === orgId && r.provider === provider)),
      listByOrg: vi.fn(async (orgId: string) => store.oauthConfigs.filter((r) => r.org_id === orgId)),
      upsert: vi.fn(async (c: Omit<OAuthConfigRow, 'created_at' | 'updated_at'>) => {
        const existing = store.oauthConfigs.find((r) => r.org_id === c.org_id && r.provider === c.provider);
        if (existing) {
          Object.assign(existing, { ...c, id: existing.id, updated_at: now() });
          return existing;
        }
        const row = { ...c, created_at: now(), updated_at: now() };
        store.oauthConfigs.push(row);
        return row;
      }),
      countClientSecretFormats: vi.fn(async () => ({
        plain: store.oauthConfigs.filter((r) => !sealedPattern.test(r.client_secret)).length,
        sealed: store.oauthConfigs.filter((r) => sealedPattern.test(r.client_secret)).length,
      })),
      listPlainClientSecrets: vi.fn(async (afterId: string, limit: number) =>
        store.oauthConfigs
          .filter((r) => !sealedPattern.test(r.client_secret) && r.id > afterId)
          .sort((a, b) => a.id.localeCompare(b.id))
          .slice(0, limit)
          .map((r) => ({ id: r.id, client_secret: r.client_secret }))),
      swapClientSecret: vi.fn(async (id: string, from: string, to: string) => {
        await store.beforeSwap?.(id);
        const row = store.oauthConfigs.find((r) => r.id === id);
        if (!row || row.client_secret !== from) return false;
        row.client_secret = to;
        return true;
      }),
      updateClientSecret: vi.fn(async (id: string, clientSecret: string) => {
        const row = store.oauthConfigs.find((r) => r.id === id);
        if (row) row.client_secret = clientSecret;
        return !!row;
      }),
      updateSigningSecret: vi.fn(async (id: string, signingSecret: string) => {
        const row = store.oauthConfigs.find((r) => r.id === id);
        if (row) row.config_json = { ...row.config_json, signing_secret: signingSecret };
        return !!row;
      }),
      countSigningSecretFormats: vi.fn(async () => {
        const values = store.oauthConfigs.map((r) => r.config_json?.signing_secret)
          .filter((v): v is string => typeof v === 'string' && v.length > 0);
        return {
          plain: values.filter((v) => !sealedPattern.test(v)).length,
          sealed: values.filter((v) => sealedPattern.test(v)).length,
        };
      }),
      listPlainSigningSecrets: vi.fn(async (afterId: string, limit: number) =>
        store.oauthConfigs
          .filter((r) => typeof r.config_json?.signing_secret === 'string' && r.config_json.signing_secret !== ''
            && !sealedPattern.test(r.config_json.signing_secret as string) && r.id > afterId)
          .sort((a, b) => a.id.localeCompare(b.id))
          .slice(0, limit)
          .map((r) => ({ id: r.id, signing_secret: r.config_json.signing_secret as string }))),
      swapSigningSecret: vi.fn(async (id: string, from: string, to: string) => {
        await store.beforeSwap?.(id);
        const row = store.oauthConfigs.find((r) => r.id === id);
        if (!row || row.config_json?.signing_secret !== from) return false;
        row.config_json = { ...row.config_json, signing_secret: to };
        return true;
      }),
    })),
  };
});

const PROJECT = 'proj_shop';
const OTHER_PROJECT = 'proj_other';
const ADMIN = 'user_admin';

/** A security service stand-in: one profile per rule, recording every decision. */
function security(profiles: Record<string, SecurityProfile> = {}) {
  const profileFor = (rule?: string) => (rule && profiles[rule]) || 'legacy';
  const decisions: string[] = [];
  return {
    decisions,
    service: {
      effectiveProfile: vi.fn(async (_scope: unknown, _governing: unknown, rule?: string) => profileFor(rule)),
      decide: vi.fn(async (rule: string) => {
        if (profileFor(rule) !== 'legacy') decisions.push(rule);
        return profileFor(rule);
      }),
      gate: vi.fn(async (rule: string) => {
        const profile = profileFor(rule);
        if (profile !== 'legacy') decisions.push(rule);
        if (profile === 'strict') throw new ForbiddenException(`Refused (rule ${rule})`);
        return profile === 'legacy' ? 'allowed' : 'recorded';
      }),
    } as unknown as SecurityService,
  };
}

function secrets(profiles: Record<string, SecurityProfile> = {}) {
  const sec = security(profiles);
  return { svc: new SecretsService({} as never, sec.service), decisions: sec.decisions };
}

function integrations(profiles: Record<string, SecurityProfile> = {}) {
  return new IntegrationsService({} as never, security(profiles).service);
}

function stored(scopeId: string, key: string): SecretRow {
  const row = store.secrets.find((r) => r.scope_id === scopeId && r.key === key);
  if (!row) throw new Error(`no row ${scopeId}/${key}`);
  return row;
}

beforeEach(() => {
  store.secrets = [];
  store.settings = new Map();
  store.integrations = [];
  store.oauthConfigs = [];
  store.beforeSwap = null;
});

describe('secret ciphertext formats', () => {
  it('writes v1 until the re-encrypt command and v2 after it, and reads both', async () => {
    const { svc } = secrets();
    await svc.create('project', PROJECT, { key: 'API_TOKEN', value: 'tok-1', type: 'env_var' });
    const v1Payload = stored(PROJECT, 'API_TOKEN').value_encrypted;
    expect(v1Payload.startsWith('v1:')).toBe(true);

    const report = await svc.reencrypt({ actor: ADMIN });
    expect(store.settings.get('secrets.ciphertext_format')).toBe('v2');
    expect(report.reencrypted.secrets).toBe(1);
    expect(stored(PROJECT, 'API_TOKEN').value_encrypted.startsWith('v2:')).toBe(true);

    await svc.create('project', PROJECT, { key: 'SECOND_TOKEN', value: 'tok-2', type: 'env_var' });
    expect(stored(PROJECT, 'SECOND_TOKEN').value_encrypted.startsWith('v2:')).toBe(true);

    // A v1 row an older replica wrote after the switch still reads.
    store.secrets.push({ ...stored(PROJECT, 'API_TOKEN'), id: 'secr_late', key: 'LATE_TOKEN', value_encrypted: v1Payload });

    const resolved = Object.fromEntries((await svc.resolveForProject(PROJECT)).map((s) => [s.key, s.value]));
    expect(resolved).toEqual({ API_TOKEN: 'tok-1', SECOND_TOKEN: 'tok-2', LATE_TOKEN: 'tok-1' });
  });

  it('binds a v2 ciphertext to its scope and key', async () => {
    store.settings.set('secrets.ciphertext_format', 'v2');
    const { svc } = secrets();
    await svc.create('project', PROJECT, { key: 'API_TOKEN', value: 'tok-1', type: 'env_var' });
    const payload = stored(PROJECT, 'API_TOKEN').value_encrypted;

    store.secrets.push({ ...stored(PROJECT, 'API_TOKEN'), id: 'secr_copy', scope_id: OTHER_PROJECT, value_encrypted: payload });
    store.secrets.push({ ...stored(PROJECT, 'API_TOKEN'), id: 'secr_rekey', key: 'OTHER_KEY', value_encrypted: payload });

    expect(await svc.resolveProjectSecretValue(PROJECT, 'API_TOKEN')).toBe('tok-1');
    await expect(svc.resolveProjectSecretValue(OTHER_PROJECT, 'API_TOKEN')).rejects.toThrow();
    await expect(svc.resolveProjectSecretValue(PROJECT, 'OTHER_KEY')).rejects.toThrow();
    expect((await svc.resolveForProject(OTHER_PROJECT)).map((s) => s.key)).not.toContain('API_TOKEN');
  });

  it('counts rows by format on a dry run and changes nothing', async () => {
    const { svc } = secrets();
    await svc.create('project', PROJECT, { key: 'API_TOKEN', value: 'tok-1', type: 'env_var' });
    store.integrations.push({
      id: 'int_a', org_id: 'org_acme', provider: 'slack', account_id: 'T1', tokens_json: { access_token: 'xoxb-1' },
      settings_json: {}, status: 'active', created_at: new Date(), updated_at: new Date(),
    });
    const before = stored(PROJECT, 'API_TOKEN').value_encrypted;

    const report = await svc.reencrypt({ actor: ADMIN, dryRun: true });

    expect(report.dry_run).toBe(true);
    expect(report.before.secrets).toMatchObject({ v1: 1, v2: 0 });
    expect(report.before.integration_tokens).toEqual({ plain: 1, sealed: 0 });
    expect(report.remaining).toBe(2);
    expect(store.settings.has('secrets.ciphertext_format')).toBe(false);
    expect(stored(PROJECT, 'API_TOKEN').value_encrypted).toBe(before);
  });

  it('keeps the new value of a row changed during re-encryption, and takes it in the next pass', async () => {
    const { svc } = secrets();
    // Another replica that still writes v1 (its format was read before the switch).
    const { svc: older } = secrets();
    await older.create('project', PROJECT, { key: 'A_TOKEN', value: 'old-a', type: 'env_var' });
    await svc.create('project', PROJECT, { key: 'B_TOKEN', value: 'old-b', type: 'env_var' });
    const aId = stored(PROJECT, 'A_TOKEN').id;

    store.beforeSwap = async (id) => {
      if (id !== aId) return;
      store.beforeSwap = null;
      await older.update('project', PROJECT, 'A_TOKEN', { value: 'new-a' });
    };
    const first = await svc.reencrypt({ actor: ADMIN });

    expect(first.reencrypted.secrets).toBe(1);
    expect(first.skipped.changed).toBe(1);
    expect(first.remaining).toBe(1);
    expect(await svc.resolveProjectSecretValue(PROJECT, 'A_TOKEN')).toBe('new-a');

    const second = await svc.reencrypt({ actor: ADMIN });
    expect(second.reencrypted.secrets).toBe(1);
    expect(second.remaining).toBe(0);
    expect(stored(PROJECT, 'A_TOKEN').value_encrypted.startsWith('v2:')).toBe(true);
    expect(await svc.resolveProjectSecretValue(PROJECT, 'A_TOKEN')).toBe('new-a');
  });
});

describe('integration tokens and OAuth client secrets at rest', () => {
  beforeEach(() => {
    store.integrations.push({
      id: 'int_slack', org_id: 'org_acme', provider: 'slack', account_id: 'T1',
      tokens_json: { access_token: 'xoxb-secret-token', team_id: 'T1' },
      settings_json: {}, status: 'active', created_at: new Date(), updated_at: new Date(),
    });
    store.oauthConfigs.push({
      id: 'oac_slack', org_id: 'org_acme', provider: 'slack', client_id: 'client-1',
      client_secret: 'plain-client-secret', config_json: {}, label: null, status: 'active', created_by: null,
      created_at: new Date(), updated_at: new Date(),
    });
  });

  it('after the command, a stored integration token is not plain JSON, and the internal routes read it', async () => {
    const { svc } = secrets();
    const report = await svc.reencrypt({ actor: ADMIN });

    const tokens = store.integrations[0].tokens_json;
    expect(typeof tokens).toBe('string');
    expect(tokens as string).toMatch(/^v2:/);
    expect(tokens as string).not.toContain('xoxb');
    expect(store.oauthConfigs[0].client_secret).toMatch(/^v2:/);
    expect(report.reencrypted).toMatchObject({ integration_tokens: 1, oauth_client_secrets: 1 });

    const integ = integrations();
    expect(await integ.getIntegrationTokens('int_slack')).toEqual({ access_token: 'xoxb-secret-token', team_id: 'T1' });
    expect((await integ.listActiveIntegrations())[0].tokens_json).toEqual({ access_token: 'xoxb-secret-token', team_id: 'T1' });
    expect((await integ.getOAuthAppConfig('org_acme', 'slack'))?.client_secret).toBe('plain-client-secret');
  });

  it('binds an integration envelope to its row', async () => {
    await secrets().svc.reencrypt({ actor: ADMIN });
    store.integrations.push({ ...store.integrations[0], id: 'int_copy', account_id: 'T2' });
    await expect(integrations().getIntegrationTokens('int_copy')).rejects.toThrow();
  });

  it('writes new tokens plain before the command and sealed after it', async () => {
    const integ = integrations();
    await integ.connectProvider('org_acme', 'google_drive', 'acct@example.com', { access_token: 'ya29-first' });
    const row = () => store.integrations.find((r) => r.provider === 'google_drive')!;
    expect(row().tokens_json).toEqual({ access_token: 'ya29-first' });

    store.settings.set('secrets.ciphertext_format', 'v2');
    const after = integrations();
    await after.connectProvider('org_acme', 'google_drive', 'acct@example.com', { access_token: 'ya29-second' });
    expect(typeof row().tokens_json).toBe('string');
    expect(await after.getIntegrationTokens(row().id)).toEqual({ access_token: 'ya29-second' });

    await after.upsertOAuthAppConfig('org_acme', 'slack', { client_id: 'client-1', client_secret: 'rotated-secret' } as never);
    expect(store.oauthConfigs[0].client_secret).toMatch(/^v2:/);
    expect((await after.getOAuthAppConfig('org_acme', 'slack'))?.client_secret).toBe('rotated-secret');
  });
});

describe('the Slack signing secret at rest', () => {
  beforeEach(() => {
    store.integrations.push({
      id: 'int_slack', org_id: 'org_acme', provider: 'slack', account_id: 'T1',
      tokens_json: { access_token: 'xoxb-secret-token', team_id: 'T1' },
      settings_json: {}, status: 'active', created_at: new Date(), updated_at: new Date(),
    });
    store.oauthConfigs.push({
      id: 'oac_slack', org_id: 'org_acme', provider: 'slack', client_id: 'client-1',
      client_secret: 'plain-client-secret', config_json: { signing_secret: 'plain-signing-secret' },
      label: null, status: 'active', created_by: null, created_at: new Date(), updated_at: new Date(),
    });
  });

  const storedSigningSecret = () => store.oauthConfigs[0].config_json.signing_secret as string;

  it('is counted while plain, and left for re-encryption', async () => {
    const report = await secrets().svc.reencrypt({ actor: ADMIN, dryRun: true });
    expect(report.before).toMatchObject({ oauth_signing_secrets: { plain: 1, sealed: 0 } });
    // The integration token, the client secret and the signing secret.
    expect(report.remaining).toBe(3);
    expect(storedSigningSecret()).toBe('plain-signing-secret');
  });

  it('is sealed by the command, bound to its row, and the gateway listing still reads it', async () => {
    const report = await secrets().svc.reencrypt({ actor: ADMIN });

    expect(storedSigningSecret()).toMatch(/^v2:/);
    expect(storedSigningSecret()).not.toContain('plain-signing');
    expect(report.reencrypted).toMatchObject({ oauth_signing_secrets: 1 });
    expect(report.after).toMatchObject({ oauth_signing_secrets: { plain: 0, sealed: 1 } });
    expect(report.remaining).toBe(0);
    const [row] = await integrations().listActiveIntegrations();
    expect(row.settings_json.signing_secret).toBe('plain-signing-secret');

    // Copied to another org's config, the envelope does not open: no secret reaches the gateway.
    store.oauthConfigs.push({ ...store.oauthConfigs[0], id: 'oac_other', org_id: 'org_other' });
    store.integrations.push({ ...store.integrations[0], id: 'int_other', org_id: 'org_other', account_id: 'T2' });
    const other = (await integrations().listActiveIntegrations()).find((r) => r.id === 'int_other');
    expect(other?.settings_json.signing_secret).toBeUndefined();
  });

  it('keeps one changed during re-encryption, and takes it in the next pass', async () => {
    const { svc } = secrets();
    let swaps = 0;
    store.beforeSwap = async (id) => {
      // The client secret's swap comes first; the signing secret's second.
      if (id !== 'oac_slack' || ++swaps !== 2) return;
      store.beforeSwap = null;
      store.oauthConfigs[0].config_json = { signing_secret: 'rotated-signing-secret' };
    };
    const first = await svc.reencrypt({ actor: ADMIN });
    expect(first.skipped.changed).toBe(1);
    expect(storedSigningSecret()).toBe('rotated-signing-secret');

    const second = await svc.reencrypt({ actor: ADMIN });
    expect(second.reencrypted).toMatchObject({ oauth_signing_secrets: 1 });
    expect(storedSigningSecret()).toMatch(/^v2:/);
    expect((await integrations().listActiveIntegrations())[0].settings_json.signing_secret).toBe('rotated-signing-secret');
  });

  it('is written plain before the command and sealed after it', async () => {
    await integrations().upsertOAuthAppConfig('org_acme', 'slack', {
      client_id: 'client-1', client_secret: 'client-secret', config: { signing_secret: 'first-signing-secret' },
    } as never);
    expect(storedSigningSecret()).toBe('first-signing-secret');

    store.settings.set('secrets.ciphertext_format', 'v2');
    const after = integrations();
    await after.upsertOAuthAppConfig('org_acme', 'slack', {
      client_id: 'client-1', client_secret: 'client-secret', config: { signing_secret: 'second-signing-secret' },
    } as never);
    expect(storedSigningSecret()).toMatch(/^v2:/);
    expect((await after.listActiveIntegrations())[0].settings_json.signing_secret).toBe('second-signing-secret');
  });
});

describe('masked secrets', () => {
  it('shows no character of the value', () => {
    const masked = maskSecretValue('abcd1234efgh5678');
    for (const ch of 'abcd1234efgh5678') expect(masked).not.toContain(ch);
  });

  it('shows the length and a fingerprint bound to the scope and key', async () => {
    const { svc } = secrets();
    await svc.create('project', PROJECT, { key: 'A_TOKEN', value: 'same-value', type: 'env_var' });
    await svc.create('project', PROJECT, { key: 'B_TOKEN', value: 'same-value', type: 'env_var' });
    await svc.create('project', OTHER_PROJECT, { key: 'A_TOKEN', value: 'same-value', type: 'env_var' });

    const a = await svc.showMasked('project', PROJECT, 'A_TOKEN');
    const b = await svc.showMasked('project', PROJECT, 'B_TOKEN');
    const other = await svc.showMasked('project', OTHER_PROJECT, 'A_TOKEN');

    expect(a.masked_value).toBe('••••••••');
    expect(a).toMatchObject({ length: 10 });
    expect(a.fingerprint).toMatch(/^[0-9a-f]{12}$/);
    expect(b.fingerprint).not.toBe(a.fingerprint);
    expect(other.fingerprint).not.toBe(a.fingerprint);
    expect((await svc.showMasked('project', PROJECT, 'A_TOKEN')).fingerprint).toBe(a.fingerprint);
  });
});

describe('secrets.legacy_ciphertext', () => {
  it('refuses a v1 value under instance strict, and writes v2 without the setting', async () => {
    const { svc: before } = secrets();
    await before.create('project', PROJECT, { key: 'OLD_TOKEN', value: 'tok-old', type: 'env_var' });

    const { svc } = secrets({ 'secrets.legacy_ciphertext': 'strict' });
    await expect(svc.resolveProjectSecretValue(PROJECT, 'OLD_TOKEN')).rejects.toBeInstanceOf(ForbiddenException);

    await svc.create('project', PROJECT, { key: 'NEW_TOKEN', value: 'tok-new', type: 'env_var' });
    expect(stored(PROJECT, 'NEW_TOKEN').value_encrypted.startsWith('v2:')).toBe(true);
    expect(await svc.resolveProjectSecretValue(PROJECT, 'NEW_TOKEN')).toBe('tok-new');
  });

  it('reads a v1 value under audit and records it', async () => {
    const { svc: before } = secrets();
    await before.create('project', PROJECT, { key: 'OLD_TOKEN', value: 'tok-old', type: 'env_var' });

    const { svc, decisions } = secrets({ 'secrets.legacy_ciphertext': 'audit' });
    expect(await svc.resolveProjectSecretValue(PROJECT, 'OLD_TOKEN')).toBe('tok-old');
    expect(decisions).toContain('secrets.legacy_ciphertext');
    expect(stored(PROJECT, 'OLD_TOKEN').value_encrypted.startsWith('v1:')).toBe(true);
  });
});

describe('secrets.value_read', () => {
  const caller = { user_id: 'user_alice' } as AuthUser;

  async function withWebhookSecret(profiles: Record<string, SecurityProfile>) {
    const made = secrets(profiles);
    await made.svc.create('project', PROJECT, { key: 'GITHUB_WEBHOOK_SECRET', value: 'whsec-1', type: 'env_var' });
    return made;
  }

  it('refuses export under strict', async () => {
    const { svc, decisions } = await withWebhookSecret({ 'secrets.value_read': 'strict' });
    await expect(svc.exportSafeSecrets(PROJECT, ['GITHUB_WEBHOOK_SECRET'], caller)).rejects.toBeInstanceOf(ForbiddenException);
    expect(decisions).toEqual(['secrets.value_read']);
  });

  it('exports and records under audit, and exports silently under legacy', async () => {
    const audit = await withWebhookSecret({ 'secrets.value_read': 'audit' });
    expect(await audit.svc.exportSafeSecrets(PROJECT, ['GITHUB_WEBHOOK_SECRET'], caller))
      .toEqual([{ key: 'GITHUB_WEBHOOK_SECRET', value: 'whsec-1' }]);
    expect(audit.decisions).toEqual(['secrets.value_read']);

    store.secrets = [];
    const legacy = await withWebhookSecret({});
    expect(await legacy.svc.exportSafeSecrets(PROJECT, ['GITHUB_WEBHOOK_SECRET'], caller))
      .toEqual([{ key: 'GITHUB_WEBHOOK_SECRET', value: 'whsec-1' }]);
    expect(legacy.decisions).toEqual([]);
  });

  it('returns a generated value once, in the ensure that creates it', async () => {
    const { svc } = secrets({ 'secrets.value_read': 'strict' });
    const first = await svc.ensureSafeSecrets(PROJECT, ['GITHUB_WEBHOOK_SECRET']);
    expect(first.created).toEqual(['GITHUB_WEBHOOK_SECRET']);
    expect(first.values).toHaveLength(1);
    expect(first.values[0].value).toBe(await svc.resolveProjectSecretValue(PROJECT, 'GITHUB_WEBHOOK_SECRET'));

    const second = await svc.ensureSafeSecrets(PROJECT, ['GITHUB_WEBHOOK_SECRET']);
    expect(second).toMatchObject({ created: [], existing: ['GITHUB_WEBHOOK_SECRET'], values: [] });
  });

  it('GitHub setup under strict returns the secret only when it creates it', async () => {
    const { svc } = secrets({ 'secrets.value_read': 'strict' });
    const projects = { findById: vi.fn(async () => ({ id: PROJECT, repo_url: 'https://github.com/acme/shop.git' })) };
    const github = new ProjectGithubController(projects as never, svc, {} as never);

    const first = await github.setup(PROJECT, {}, caller);
    expect(first.secret).toBe(await svc.resolveProjectSecretValue(PROJECT, 'GITHUB_WEBHOOK_SECRET'));

    const again = await github.setup(PROJECT, {}, caller);
    expect(again.secret).toBeNull();

    const regenerated = await github.setup(PROJECT, { regenerate: true }, caller);
    expect(regenerated.secret).toBe(await svc.resolveProjectSecretValue(PROJECT, 'GITHUB_WEBHOOK_SECRET'));
    expect(regenerated.secret).not.toBe(first.secret);
  });

  it('GitHub setup under audit still returns an existing secret', async () => {
    const { svc } = await withWebhookSecret({ 'secrets.value_read': 'audit' });
    const projects = { findById: vi.fn(async () => ({ id: PROJECT, repo_url: 'https://github.com/acme/shop.git' })) };
    const github = new ProjectGithubController(projects as never, svc, {} as never);
    expect((await github.setup(PROJECT, {}, caller)).secret).toBe('whsec-1');
  });
});
