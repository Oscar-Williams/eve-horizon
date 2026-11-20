import { createHash } from 'node:crypto';
import { describe, expect, it, vi } from 'vitest';
import {
  INTERNAL_TOKEN_HEADER,
  SERVICE_KEY_HEADER,
  hasInternalCredential,
  identifyInternalCaller,
  internalApiFetch,
  internalAuthHeaders,
  internalKeyHash,
  judgeInternalCall,
} from '../api-client/index';
import {
  assertInternalApiKeyConfigured,
  legacyInternalKeyJudge,
  registerInternalAuthHook,
} from '../service-bootstrap';

const CORE = 'core-key-0123456789';
const GATEWAY = 'gateway-key-0123456789';
const SSO = 'sso-key-0123456789';
const DELIVER = 'deliver-key-0123456789';
const LEGACY = 'legacy-internal-key';
const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

/** The API's environment: the core key, and only hashes of the gateway and SSO keys. */
const apiEnv = {
  EVE_INTERNAL_CORE_KEY: CORE,
  EVE_INTERNAL_CALLER_HASHES: `gateway:${sha(GATEWAY)},sso:${sha(SSO)}`,
};

describe('internal service keys: what a caller sends', () => {
  it('a core service sends its key as core.<key>, and the legacy key while it still holds one', () => {
    expect(internalAuthHeaders({ env: { EVE_INTERNAL_CORE_KEY: CORE, EVE_INTERNAL_API_KEY: LEGACY } })).toEqual({
      [SERVICE_KEY_HEADER]: `core.${CORE}`,
      [INTERNAL_TOKEN_HEADER]: LEGACY,
    });
    expect(internalAuthHeaders({ env: { EVE_INTERNAL_CORE_KEY: CORE } })).toEqual({
      [SERVICE_KEY_HEADER]: `core.${CORE}`,
    });
    expect(internalAuthHeaders({ env: { EVE_INTERNAL_API_KEY: LEGACY } })).toEqual({
      [INTERNAL_TOKEN_HEADER]: LEGACY,
    });
    expect(internalAuthHeaders({ env: {} })).toEqual({});
  });

  it('the gateway and the SSO send their own key, never the core key even when it is in their env', () => {
    const env = { EVE_INTERNAL_CORE_KEY: CORE, EVE_INTERNAL_GATEWAY_KEY: GATEWAY, EVE_INTERNAL_SSO_KEY: SSO };
    expect(internalAuthHeaders({ service: 'gateway', env })).toEqual({ [SERVICE_KEY_HEADER]: `gateway.${GATEWAY}` });
    expect(internalAuthHeaders({ service: 'sso', env })).toEqual({ [SERVICE_KEY_HEADER]: `sso.${SSO}` });
  });

  it('a delivery to the gateway sends the deliver key and the legacy key, never the core key', () => {
    const env = { EVE_INTERNAL_CORE_KEY: CORE, EVE_INTERNAL_DELIVER_KEY: DELIVER, EVE_INTERNAL_API_KEY: LEGACY };
    expect(internalAuthHeaders({ service: 'deliver', env })).toEqual({
      [SERVICE_KEY_HEADER]: `deliver.${DELIVER}`,
      [INTERNAL_TOKEN_HEADER]: LEGACY,
    });
    // Without its own key it falls back to the legacy key only.
    expect(internalAuthHeaders({ service: 'deliver', env: { EVE_INTERNAL_CORE_KEY: CORE, EVE_INTERNAL_API_KEY: LEGACY } }))
      .toEqual({ [INTERNAL_TOKEN_HEADER]: LEGACY });
    expect(internalAuthHeaders({ service: 'deliver', env: { EVE_INTERNAL_CORE_KEY: CORE } })).toEqual({});
  });

  it('knows whether a service holds any internal credential', () => {
    expect(hasInternalCredential({ env: { EVE_INTERNAL_CORE_KEY: CORE } })).toBe(true);
    expect(hasInternalCredential({ env: { EVE_INTERNAL_API_KEY: LEGACY } })).toBe(true);
    expect(hasInternalCredential({ service: 'gateway', env: { EVE_INTERNAL_CORE_KEY: CORE } })).toBe(false);
    expect(hasInternalCredential({ service: 'gateway', env: { EVE_INTERNAL_GATEWAY_KEY: GATEWAY } })).toBe(true);
    expect(hasInternalCredential({ env: {} })).toBe(false);
  });

  it('internalApiFetch sends the named service key and the legacy key', async () => {
    const fetchMock = vi.fn(async () => new Response('{}'));
    vi.stubGlobal('fetch', fetchMock);
    vi.stubEnv('EVE_INTERNAL_GATEWAY_KEY', GATEWAY);
    vi.stubEnv('EVE_INTERNAL_CORE_KEY', CORE);
    vi.stubEnv('EVE_INTERNAL_API_KEY', LEGACY);
    try {
      await internalApiFetch('/internal/integrations/active', { baseUrl: 'http://api.test', service: 'gateway' });
      const headers = (fetchMock.mock.calls[0] as unknown as [string, { headers: Record<string, string> }])[1].headers;
      expect(headers[SERVICE_KEY_HEADER]).toBe(`gateway.${GATEWAY}`);
      expect(headers[INTERNAL_TOKEN_HEADER]).toBe(LEGACY);
    } finally {
      vi.unstubAllGlobals();
      vi.unstubAllEnvs();
    }
  });
});

describe('internal service keys: what a callee accepts', () => {
  it('hashes a key with SHA-256, as EVE_INTERNAL_CALLER_HASHES lists it', () => {
    expect(internalKeyHash(GATEWAY)).toBe(sha(GATEWAY));
  });

  it('accepts the core key it holds, and the gateway and SSO keys by their hashes', () => {
    expect(identifyInternalCaller(`core.${CORE}`, apiEnv)).toBe('core');
    expect(identifyInternalCaller(`gateway.${GATEWAY}`, apiEnv)).toBe('gateway');
    expect(identifyInternalCaller(`sso.${SSO}`, apiEnv)).toBe('sso');
  });

  it('accepts the core key by its hash when the callee does not hold it', () => {
    expect(identifyInternalCaller(`core.${CORE}`, { EVE_INTERNAL_CALLER_HASHES: `core:${sha(CORE)}` })).toBe('core');
  });

  it('accepts the deliver key by its hash, and never under another service name', () => {
    const gatewayEnv = { EVE_INTERNAL_CALLER_HASHES: `deliver:${sha(DELIVER)}` };
    expect(identifyInternalCaller(`deliver.${DELIVER}`, gatewayEnv)).toBe('deliver');
    expect(identifyInternalCaller(`core.${DELIVER}`, gatewayEnv)).toBeNull();
    expect(identifyInternalCaller(`deliver.${CORE}`, gatewayEnv)).toBeNull();
  });

  it('refuses a wrong key, a key under another service name, an unknown service and malformed values', () => {
    expect(identifyInternalCaller(`gateway.${GATEWAY}x`, apiEnv)).toBeNull();
    expect(identifyInternalCaller(`sso.${GATEWAY}`, apiEnv)).toBeNull();
    expect(identifyInternalCaller(`core.${GATEWAY}`, apiEnv)).toBeNull();
    expect(identifyInternalCaller(`admin.${CORE}`, apiEnv)).toBeNull();
    expect(identifyInternalCaller(CORE, apiEnv)).toBeNull();
    expect(identifyInternalCaller('core.', apiEnv)).toBeNull();
    expect(identifyInternalCaller([`core.${CORE}`], apiEnv)).toBeNull();
    expect(identifyInternalCaller(undefined, apiEnv)).toBeNull();
    expect(identifyInternalCaller(`gateway.${GATEWAY}`, { EVE_INTERNAL_CORE_KEY: CORE })).toBeNull();
  });

  it('judges a call with both headers on the service key', () => {
    const env = { ...apiEnv, EVE_INTERNAL_API_KEY: LEGACY };
    expect(judgeInternalCall({ [SERVICE_KEY_HEADER]: `gateway.${GATEWAY}`, [INTERNAL_TOKEN_HEADER]: LEGACY }, { env }))
      .toEqual({ kind: 'service', service: 'gateway' });
    expect(judgeInternalCall({ [INTERNAL_TOKEN_HEADER]: LEGACY }, { env }))
      .toEqual({ kind: 'legacy', serviceKeyRefused: false });
    // A service key the callee cannot verify yet (no hash configured) falls back to the legacy key.
    expect(judgeInternalCall({ [SERVICE_KEY_HEADER]: `gateway.${GATEWAY}`, [INTERNAL_TOKEN_HEADER]: LEGACY }, {
      env: { EVE_INTERNAL_API_KEY: LEGACY },
    })).toEqual({ kind: 'legacy', serviceKeyRefused: true });
    expect(judgeInternalCall({ [SERVICE_KEY_HEADER]: 'gateway.wrong' }, { env })).toBeNull();
    expect(judgeInternalCall({}, { env })).toBeNull();
  });
});

describe('the internal-only service hook (worker, agent runtime)', () => {
  function run(
    options: Parameters<typeof registerInternalAuthHook>[1],
    headers: Record<string, string>,
    url = '/invoke',
  ): Promise<number> {
    let hook: (request: unknown, reply: unknown, done: () => void) => void = () => undefined;
    registerInternalAuthHook({ addHook: (_name: string, fn: typeof hook) => { hook = fn; } } as never, options);
    return new Promise((resolve) => {
      const reply = { code(code: number) { resolve(code); return reply; }, send() { return reply; } };
      hook({ url, headers }, reply, () => resolve(200));
    });
  }

  it('accepts the core key with no legacy key configured', async () => {
    expect(await run({ key: '', env: { EVE_INTERNAL_CORE_KEY: CORE } }, { [SERVICE_KEY_HEADER]: `core.${CORE}` })).toBe(200);
  });

  it('refuses the gateway and SSO keys, even with the legacy key beside them', async () => {
    const env = { ...apiEnv };
    expect(await run({ key: LEGACY, env }, { [SERVICE_KEY_HEADER]: `gateway.${GATEWAY}`, [INTERNAL_TOKEN_HEADER]: LEGACY }))
      .toBe(401);
    expect(await run({ key: LEGACY, env }, { [SERVICE_KEY_HEADER]: `sso.${SSO}` })).toBe(401);
  });

  it('asks the legacy-key judge about a call with only the legacy key, and not about a core call', async () => {
    const onLegacyKey = vi.fn(async () => false);
    const env = { EVE_INTERNAL_CORE_KEY: CORE };
    expect(await run({ key: LEGACY, env, onLegacyKey }, { [INTERNAL_TOKEN_HEADER]: LEGACY })).toBe(401);
    expect(onLegacyKey).toHaveBeenCalledWith('/invoke');
    onLegacyKey.mockClear();
    expect(await run({ key: LEGACY, env, onLegacyKey }, { [SERVICE_KEY_HEADER]: `core.${CORE}` })).toBe(200);
    expect(onLegacyKey).not.toHaveBeenCalled();
    onLegacyKey.mockResolvedValue(true);
    expect(await run({ key: LEGACY, env, onLegacyKey }, { [INTERNAL_TOKEN_HEADER]: LEGACY })).toBe(200);
  });

  it('starts in production with the core key alone', () => {
    const warn = vi.fn();
    expect(() => assertInternalApiKeyConfigured({ warn }, 'WORKER', { NODE_ENV: 'production', EVE_INTERNAL_CORE_KEY: CORE }))
      .not.toThrow();
    expect(warn).not.toHaveBeenCalled();
  });
});

describe('legacyInternalKeyJudge', () => {
  it('refuses under strict, allows otherwise, and asks at most once per window', async () => {
    let now = 1_000;
    const decide = vi.fn(async () => 'audit' as const);
    const judge = legacyInternalKeyJudge(decide, { cacheMs: 30_000, now: () => now });
    expect(await judge('/invoke')).toBe(true);
    expect(await judge('/deploy')).toBe(true);
    expect(decide).toHaveBeenCalledTimes(1);
    expect(decide).toHaveBeenCalledWith('/invoke');

    decide.mockResolvedValue('strict' as never);
    now += 30_001;
    expect(await judge('/invoke')).toBe(false);
    expect(decide).toHaveBeenCalledTimes(2);
  });

  it('keeps today\'s behaviour when the profile cannot be read', async () => {
    const judge = legacyInternalKeyJudge(async () => { throw new Error('database unavailable'); });
    expect(await judge('/invoke')).toBe(true);
  });
});
