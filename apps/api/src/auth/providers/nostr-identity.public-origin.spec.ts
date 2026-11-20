import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// NIP-98: the URL a request is checked against comes from the API's
// configured public origin (EVE_PUBLIC_API_URL), never from Host or
// X-Forwarded-Host, so an event signed for another host cannot be replayed
// here. Without the setting, rule auth.nip98_public_url (instance) records
// each such request under audit and refuses it under strict: only a request
// that passes every other check (signature, kind, URL, method, payload and
// time), so a forged or stale one records nothing.

const mocks = vi.hoisted(() => ({
  decide: vi.fn(),
  profile: 'audit' as string,
  verify: vi.fn(),
  assertNotReplayed: vi.fn(async () => {}),
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  replayStoreQueries: vi.fn(() => ({ assertNotReplayed: mocks.assertNotReplayed })),
  decideSecurityRule: mocks.decide,
}));

vi.mock('@eve/shared', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/shared')>()),
  verifyNostrEvent: mocks.verify,
}));

import { NostrIdentityProvider } from './nostr-identity.provider';

const HOST = 'api.eve.example';

function request(host: string, overrides: { method?: string; tags?: string[][]; created_at?: number; kind?: number } = {}) {
  const event = {
    id: 'e1',
    pubkey: 'ab'.repeat(32),
    kind: overrides.kind ?? 27235,
    created_at: overrides.created_at ?? Math.floor(Date.now() / 1000),
    tags: overrides.tags ?? [['u', `https://${host}/auth/me`], ['method', 'GET']],
    content: '',
    sig: '00',
  };
  return {
    headers: { authorization: `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}`, host, 'x-forwarded-host': host },
    hostname: host,
    protocol: 'https',
    url: '/auth/me',
    method: overrides.method ?? 'GET',
  };
}

async function verify(req: ReturnType<typeof request>) {
  const provider = new NostrIdentityProvider({} as never);
  const credential = provider.extractFromRequest(req);
  expect(credential).not.toBeNull();
  return provider.verifyRequestCredential(credential!);
}

describe('NIP-98 public origin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.profile = 'audit';
    mocks.decide.mockImplementation(async () => mocks.profile);
    mocks.verify.mockReturnValue(true);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('checks the request against the configured origin whatever the headers say', () => {
    vi.stubEnv('EVE_PUBLIC_API_URL', 'https://api.eve.example');
    const provider = new NostrIdentityProvider({} as never);
    const credential = provider.extractFromRequest(request('evil.example')) as { url: string } | null;
    expect(credential?.url).toBe('https://api.eve.example/auth/me');
  });

  it('refuses a request under instance strict when no origin is configured', async () => {
    vi.stubEnv('EVE_PUBLIC_API_URL', '');
    mocks.profile = 'strict';

    await expect(verify(request(HOST))).resolves.toBeNull();
    expect(mocks.decide).toHaveBeenCalledWith(expect.anything(), 'auth.nip98_public_url', expect.objectContaining({ governing: 'instance' }));
    expect(mocks.assertNotReplayed).not.toHaveBeenCalled();
  });

  it('records the request under audit and accepts it', async () => {
    vi.stubEnv('EVE_PUBLIC_API_URL', '');

    await expect(verify(request(HOST))).resolves.toMatchObject({ provider: 'nostr', externalId: 'ab'.repeat(32) });
    expect(mocks.decide).toHaveBeenCalledTimes(1);
    expect(mocks.decide).toHaveBeenCalledWith(expect.anything(), 'auth.nip98_public_url', expect.objectContaining({
      detail: { url: `https://${HOST}/auth/me` },
    }));
  });

  it.each([
    ['a signature that does not verify', () => { mocks.verify.mockReturnValue(false); return request(HOST); }],
    ['another kind of event', () => request(HOST, { kind: 1 })],
    ['a URL signed for another host', () => request(HOST, { tags: [['u', 'https://other.example/auth/me'], ['method', 'GET']] })],
    ['another method', () => request(HOST, { method: 'DELETE' })],
    ['a body that does not match its hash', () => request(HOST, { method: 'POST', tags: [['u', `https://${HOST}/auth/me`], ['method', 'POST'], ['payload', '00']] })],
    ['an event outside the time window', () => request(HOST, { created_at: Math.floor(Date.now() / 1000) - 600 })],
  ])('records nothing for %s', async (_label, build) => {
    vi.stubEnv('EVE_PUBLIC_API_URL', '');

    await expect(verify(build())).resolves.toBeNull();
    expect(mocks.decide).not.toHaveBeenCalled();
  });
});
