import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { getHarnessAuthStatus } from '../auth.js';
import { selectAvailableHarness } from '../select.js';

beforeEach(() => {
  vi.stubEnv('GEMINI_API_KEY', 'gk-host');
  vi.stubEnv('GOOGLE_API_KEY', '');
});

afterEach(() => {
  vi.unstubAllEnvs();
});

describe('harness credentials without host fallback', () => {
  it("count the process environment by default, and only the given secrets when host credentials are off", () => {
    expect(getHarnessAuthStatus('gemini', {}).available).toBe(true);
    expect(getHarnessAuthStatus('gemini', {}, { hostCredentials: false }).available).toBe(false);
    expect(getHarnessAuthStatus('gemini', { GEMINI_API_KEY: 'gk-project' }, { hostCredentials: false }).available).toBe(true);
  });

  it('pick the first preference the given secrets cover when host credentials are off', () => {
    const selection = selectAvailableHarness({
      projectPreference: ['gemini', 'zai'],
      env: { Z_AI_API_KEY: 'zk-project' },
      hostCredentials: false,
    });

    expect(selection.harness).toBe('zai');
  });
});
