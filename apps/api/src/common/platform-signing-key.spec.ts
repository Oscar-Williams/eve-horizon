import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { platformSigningKeys } from './platform-signing-key.js';
import { IntegrationsService } from '../integrations/integrations.service.js';

/**
 * Tokens the API signs for itself (identity link tokens, Slack install links)
 * are signed with a key derived from the core key, so the legacy internal key
 * can be removed. While the legacy key is set, tokens it signed still verify.
 */
describe('platformSigningKeys', () => {
  it('signs with a key derived from the core key, per purpose, and verifies the legacy key while it is set', () => {
    const keys = platformSigningKeys('slack-install', { EVE_INTERNAL_CORE_KEY: 'core-key', EVE_INTERNAL_API_KEY: 'legacy-key' });
    expect(keys.sign).toBeDefined();
    expect(keys.sign).not.toBe('core-key');
    expect(keys.sign).not.toBe(platformSigningKeys('identity-link', { EVE_INTERNAL_CORE_KEY: 'core-key' }).sign);
    expect(keys.verify).toEqual([keys.sign, 'legacy-key']);
  });

  it('signs with the legacy key until a core key is set', () => {
    expect(platformSigningKeys('slack-install', { EVE_INTERNAL_API_KEY: 'legacy-key' })).toEqual({
      sign: 'legacy-key',
      verify: ['legacy-key'],
    });
    expect(platformSigningKeys('slack-install', {})).toEqual({ sign: undefined, verify: [] });
  });
});

describe('Slack install links across the key change', () => {
  beforeEach(() => {
    vi.stubEnv('DATABASE_URL', 'postgres://user:pass@localhost:5432/eve_test');
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  const service = () => new IntegrationsService({} as never);

  it('signs and validates with the core key alone', () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    vi.stubEnv('EVE_INTERNAL_CORE_KEY', 'core-key');
    const { token } = service().generateSlackInstallToken('org_acme');
    expect(service().validateSlackInstallToken(token)).toEqual({ orgId: 'org_acme' });
  });

  it('still validates a link signed with the legacy key while that key is set', () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', 'legacy-key');
    const { token } = service().generateSlackInstallToken('org_acme');
    vi.stubEnv('EVE_INTERNAL_CORE_KEY', 'core-key');
    expect(service().validateSlackInstallToken(token)).toEqual({ orgId: 'org_acme' });
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    expect(service().validateSlackInstallToken(token)).toBeNull();
  });
});
