import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

// NIP-98: the URL a request is checked against comes from the API's
// configured public origin (EVE_PUBLIC_API_URL), never from Host or
// X-Forwarded-Host, so an event signed for another host cannot be replayed
// here. Without the setting, rule auth.nip98_public_url (instance) records
// each such request under audit and refuses it under strict.

const mocks = vi.hoisted(() => ({ decide: vi.fn(), profile: 'audit' as string }));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  replayStoreQueries: vi.fn(() => ({ assertNotReplayed: vi.fn(async () => {}) })),
  decideSecurityRule: mocks.decide,
}));

import { NostrIdentityProvider } from './nostr-identity.provider';

function request(host: string) {
  const event = { id: 'e1', pubkey: 'ab'.repeat(32), kind: 27235, created_at: Math.floor(Date.now() / 1000), tags: [], content: '', sig: '00' };
  return {
    headers: { authorization: `Nostr ${Buffer.from(JSON.stringify(event)).toString('base64')}`, host, 'x-forwarded-host': host },
    hostname: host,
    protocol: 'https',
    url: '/auth/me',
    method: 'GET',
  };
}

describe('NIP-98 public origin', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.decide.mockImplementation(async () => mocks.profile);
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
    const provider = new NostrIdentityProvider({} as never);
    const credential = provider.extractFromRequest(request('api.eve.example'));
    expect(credential).not.toBeNull();
    await expect(provider.verifyRequestCredential(credential!)).resolves.toBeNull();
    expect(mocks.decide).toHaveBeenCalledWith(expect.anything(), 'auth.nip98_public_url', expect.objectContaining({ governing: 'instance' }));
  });
});
