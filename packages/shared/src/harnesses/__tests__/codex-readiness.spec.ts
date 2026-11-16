import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { getHarnessAuthStatus } from '../auth.js';

afterEach(() => vi.unstubAllEnvs());

describe('codex readiness', () => {
  it('counts operator auth in CODEX_AUTH_JSON_B64', async () => {
    // An empty HOME, so a developer's own codex login on this machine cannot count instead.
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-readiness-empty-'));
    vi.stubEnv('HOME', home);
    vi.stubEnv('EVE_RUNTIME', 'k8s');
    expect(getHarnessAuthStatus('codex', {}).available).toBe(false);
    expect(getHarnessAuthStatus('codex', { CODEX_AUTH_JSON_B64: 'e30=' }).available).toBe(true);
    await fs.rm(home, { recursive: true, force: true });
  });

  it("does not count an auth.json in a k8s runtime's own HOME, which jobs never use", async () => {
    const home = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-readiness-'));
    await fs.mkdir(path.join(home, '.codex'), { recursive: true });
    await fs.writeFile(path.join(home, '.codex', 'auth.json'), '{"tokens":{"access_token":"x"}}');
    vi.stubEnv('HOME', home);

    vi.stubEnv('EVE_RUNTIME', 'k8s');
    expect(getHarnessAuthStatus('codex', {}).available).toBe(false);
    vi.stubEnv('EVE_RUNTIME', '');
    expect(getHarnessAuthStatus('codex', {}).available).toBe(true);
    await fs.rm(home, { recursive: true, force: true });
  });
});
