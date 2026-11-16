import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { HarnessInvocation } from '../../types/harness.js';
import type { SecretResolveItem } from '../../schemas/secret.js';
import { cleanupJobSecretArtifacts, prepareGitAuth } from '../workspace-secrets.js';
import { serviceGitEnv } from '../../process-isolation.js';

const TOKEN = 'ghs_exampleInstallationToken123';
const created: HarnessInvocation[] = [];

function invocation(repoUrl: string, secrets_allowlist?: string[]): HarnessInvocation {
  const inv = {
    attemptId: `att-git-${Math.random().toString(36).slice(2)}`,
    jobId: 'proj-a1b2c3d4',
    projectId: 'proj_test',
    text: 'prompt',
    workspacePath: path.join(os.tmpdir(), `eve-git-auth-${Math.random().toString(36).slice(2)}`),
    repoUrl,
    ...(secrets_allowlist ? { secrets_allowlist } : {}),
  } as HarnessInvocation;
  created.push(inv);
  return inv;
}

function secret(key: string, value: string, type: SecretResolveItem['type'] = 'env_var'): SecretResolveItem {
  return { key, value, type, scope_type: 'project', scope_id: 'proj_test' } as SecretResolveItem;
}

afterEach(async () => {
  for (const inv of created.splice(0)) {
    await cleanupJobSecretArtifacts(inv);
    await fs.rm(inv.workspacePath, { recursive: true, force: true });
  }
});

describe('prepareGitAuth with a secrets allowlist', () => {
  const https = 'https://github.com/org/repo.git';

  it('embeds the token in the clone URL when no allowlist is declared (unchanged)', async () => {
    const auth = await prepareGitAuth(invocation(https), [secret('GITHUB_TOKEN', TOKEN)]);
    expect(auth?.cloneUrl).toContain(TOKEN);
  });

  it('embeds the token when the allowlist names it', async () => {
    const auth = await prepareGitAuth(invocation(https, ['GITHUB_TOKEN']), [secret('GITHUB_TOKEN', TOKEN)]);
    expect(auth?.cloneUrl).toContain(TOKEN);
  });

  it('keeps a token the allowlist leaves out off the clone URL, so it never lands in .git/config', async () => {
    const auth = await prepareGitAuth(invocation(https, ['ANTHROPIC_API_KEY']), [secret('GITHUB_TOKEN', TOKEN)]);

    expect(auth?.cloneUrl).toBeUndefined();
    // The platform's own git calls authenticate through an extra header in their env only.
    const env = serviceGitEnv(auth?.env ?? {});
    const header = Object.entries(env).find(([key, value]) => key.startsWith('GIT_CONFIG_KEY_') && value === 'http.https://github.com/.extraheader');
    expect(header).toBeDefined();
    const valueKey = header![0].replace('KEY', 'VALUE');
    expect(env[valueKey]).toBe(`AUTHORIZATION: basic ${Buffer.from(`x-access-token:${TOKEN}`).toString('base64')}`);
  });

  it('writes an SSH key the allowlist leaves out outside the workspace', async () => {
    const inv = invocation('git@github.com:org/repo.git', ['ANTHROPIC_API_KEY']);
    const auth = await prepareGitAuth(inv, [secret('DEPLOY_KEY', 'ssh-key-material', 'ssh_key')]);

    const keyPath = /-i (\S+)/.exec(auth?.env?.GIT_SSH_COMMAND ?? '')?.[1];
    expect(keyPath).toBeDefined();
    expect(path.resolve(keyPath!).startsWith(path.resolve(inv.workspacePath) + path.sep)).toBe(false);
  });
});

describe('the clone-only auth header', () => {
  it('is never built for a host that only contains "github.com"', async () => {
    const auth = await prepareGitAuth(
      invocation('https://github.com.attacker.example/org/repo.git', ['ANTHROPIC_API_KEY']),
      [secret('GITHUB_TOKEN', TOKEN)],
    );
    expect(JSON.stringify(auth ?? {})).not.toContain(Buffer.from(`x-access-token:${TOKEN}`).toString('base64'));
  });
});

describe('serviceGitEnv with caller git config', () => {
  it('appends caller config and keeps hooks and fsmonitor disabled last', () => {
    const env = serviceGitEnv({
      GIT_CONFIG_COUNT: '2',
      GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
      GIT_CONFIG_VALUE_0: 'AUTHORIZATION: basic abc',
      GIT_CONFIG_KEY_1: 'core.hooksPath',
      GIT_CONFIG_VALUE_1: '/tmp/evil-hooks',
    }, { PATH: '/usr/bin' }, { platform: 'darwin' });

    expect(env.GIT_CONFIG_COUNT).toBe('4');
    expect(env.GIT_CONFIG_KEY_0).toBe('http.https://github.com/.extraheader');
    expect(env.GIT_CONFIG_KEY_1).toBe('core.hooksPath');
    // Later entries win for single-valued keys, so the platform's own come last.
    expect(env.GIT_CONFIG_KEY_2).toBe('core.hooksPath');
    expect(env.GIT_CONFIG_VALUE_2).toBe('/dev/null');
    expect(env.GIT_CONFIG_KEY_3).toBe('core.fsmonitor');
  });
});
