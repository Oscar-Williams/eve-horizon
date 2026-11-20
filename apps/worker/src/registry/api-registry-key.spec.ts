import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { registryKeyVersion } from '@eve/shared';
import { fetchApiRegistryKeyVersion, registryKeyMismatch } from './api-registry-key.js';

/**
 * Before the worker writes a pull secret, it checks the API verifies
 * credentials with the key the worker signs with: a secret signed with any
 * other key would be refused at the next pull.
 */
describe('the API registry key version', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    fetchMock.mockReset();
    vi.stubGlobal('fetch', fetchMock);
    vi.stubEnv('EVE_API_URL', 'http://api.test');
    vi.stubEnv('EVE_INTERNAL_CORE_KEY', 'core-key');
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.unstubAllEnvs();
  });

  it('asks the API with the core key', async () => {
    fetchMock.mockResolvedValue(new Response(JSON.stringify({ key_version: 'abc123' }), { status: 200 }));
    await expect(fetchApiRegistryKeyVersion()).resolves.toBe('abc123');
    const [url, init] = fetchMock.mock.calls[0] as [string, { headers: Record<string, string> }];
    expect(url).toBe('http://api.test/internal/registry/key-version');
    expect(init.headers['x-eve-service-key']).toBe('core.core-key');
  });

  it('reads an API without the route as one that verifies with the internal key only', async () => {
    fetchMock.mockResolvedValue(new Response('not found', { status: 404 }));
    await expect(fetchApiRegistryKeyVersion()).resolves.toBe('internal');
  });

  it('fails when the API cannot say', async () => {
    fetchMock.mockResolvedValue(new Response('unavailable', { status: 503 }));
    await expect(fetchApiRegistryKeyVersion()).rejects.toThrow(/registry key version/);
  });

  it('names a mismatch, and nothing when the versions agree', () => {
    const version = registryKeyVersion('registry-credential-key');
    expect(registryKeyMismatch(version, version)).toBeNull();
    expect(registryKeyMismatch('internal', 'internal')).toBeNull();
    expect(registryKeyMismatch(version, 'internal')).toMatch(/registry key version/);
    expect(registryKeyMismatch(version, null)).toMatch(/registry key version/);
    expect(registryKeyMismatch(version, undefined)).toMatch(/registry key version/);
  });
});
