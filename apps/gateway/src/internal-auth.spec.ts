import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { INTERNAL_TOKEN_HEADER, SERVICE_KEY_HEADER } from '@eve/shared';
import { assertDeliverCaller } from './internal-auth.js';

/**
 * Who may call the gateway's internal routes: the deliver key, or the
 * legacy key while `internal.service_key` allows it. The core key itself is
 * never accepted, but an API pod of the release before the deliver key
 * sends its core key beside the legacy key; for one release that call is
 * judged on the legacy key alone.
 */

const CORE = 'core-key-0123456789';
const DELIVER = 'deliver-key-0123456789';
const LEGACY = 'legacy-internal-key';
const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

beforeEach(() => {
  // A gateway that can verify the core key: it still holds it (envFrom: eve-app).
  vi.stubEnv('EVE_INTERNAL_CORE_KEY', CORE);
  vi.stubEnv('EVE_INTERNAL_CALLER_HASHES', `deliver:${sha(DELIVER)}`);
  vi.stubEnv('EVE_INTERNAL_API_KEY', LEGACY);
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('assertDeliverCaller', () => {
  it('accepts the deliver key without asking about the legacy key', async () => {
    const legacyAllowed = vi.fn(async () => false);
    await expect(assertDeliverCaller({ [SERVICE_KEY_HEADER]: `deliver.${DELIVER}` }, '/internal/deliver', legacyAllowed)).resolves.toBeUndefined();
    expect(legacyAllowed).not.toHaveBeenCalled();
  });

  it('judges a core key sent beside the legacy key on the legacy key, as a legacy-only call', async () => {
    const legacyAllowed = vi.fn(async () => true);
    const headers = { [SERVICE_KEY_HEADER]: `core.${CORE}`, [INTERNAL_TOKEN_HEADER]: LEGACY };
    await expect(assertDeliverCaller(headers, '/internal/deliver', legacyAllowed)).resolves.toBeUndefined();
    expect(legacyAllowed).toHaveBeenCalledWith('/internal/deliver');

    legacyAllowed.mockResolvedValue(false);
    await expect(assertDeliverCaller(headers, '/internal/deliver', legacyAllowed)).rejects.toThrow(/internal\.service_key/);
  });

  it('never accepts the core key on its own, or beside a wrong legacy key', async () => {
    const legacyAllowed = vi.fn(async () => true);
    await expect(assertDeliverCaller({ [SERVICE_KEY_HEADER]: `core.${CORE}` }, '/internal/deliver', legacyAllowed))
      .rejects.toThrow(/invalid internal token/);
    await expect(assertDeliverCaller({ [SERVICE_KEY_HEADER]: `core.${CORE}`, [INTERNAL_TOKEN_HEADER]: 'wrong' }, '/internal/deliver', legacyAllowed))
      .rejects.toThrow(/invalid internal token/);
    expect(legacyAllowed).not.toHaveBeenCalled();
  });
});
