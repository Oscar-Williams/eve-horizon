import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { operatorCodexAuth, writeJobCodexAuth } from '../codex-auth.js';

const created: string[] = [];
afterEach(async () => {
  vi.unstubAllEnvs();
  await Promise.all(created.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

async function tmp(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  created.push(dir);
  return dir;
}

describe('writeJobCodexAuth', () => {
  it("keeps auth.json in the repo's Codex config dir out of git, so a commit policy never commits it", async () => {
    const repo = await tmp('eve-codex-repo-');
    execFileSync('git', ['init', '-q'], { cwd: repo, env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null' } });
    const jobUserHome = await tmp('eve-codex-home-');
    const configDir = path.join(repo, '.agent', 'harnesses', 'codex');

    await writeJobCodexAuth('{"tokens":{"refresh_token":"rt"}}', { configDir, jobUserHome, repoPath: repo });
    await writeJobCodexAuth('{"tokens":{"refresh_token":"rt"}}', { configDir, jobUserHome, repoPath: repo });

    const status = execFileSync('git', ['status', '--porcelain', '--untracked-files=all'], {
      cwd: repo, env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null' },
    }).toString();
    expect(status).not.toContain('auth.json');
    const exclude = await fs.readFile(path.join(repo, '.git', 'info', 'exclude'), 'utf8');
    expect(exclude.split('\n').filter((line) => line === '/.agent/harnesses/codex/auth.json')).toHaveLength(1);
    await expect(fs.readFile(path.join(jobUserHome, '.codex', 'auth.json'), 'utf8')).resolves.toContain('rt');
  });
});

describe('operatorCodexAuth', () => {
  it("reads operator Codex auth from the service's own env, which jobs cannot write", async () => {
    const json = '{"tokens":{"access_token":"op"}}';
    await expect(operatorCodexAuth({ env: { CODEX_AUTH_JSON: Buffer.from(json).toString('base64') } })).resolves.toBe(json);
    await expect(operatorCodexAuth({ env: { CODEX_AUTH_JSON_B64: Buffer.from(json).toString('base64') } })).resolves.toBe(json);
    const fromToken = JSON.parse((await operatorCodexAuth({ env: { CODEX_OAUTH_ACCESS_TOKEN: 'at', CODEX_OAUTH_ACCOUNT_ID: 'acct' } }))!);
    expect(fromToken).toEqual({ tokens: { access_token: 'at', account_id: 'acct' } });
  });

  it("reads a developer's codex login only when the services run outside k8s", async () => {
    const home = await tmp('eve-dev-home-');
    await fs.mkdir(path.join(home, '.codex'), { recursive: true });
    await fs.writeFile(path.join(home, '.codex', 'auth.json'), '{"tokens":{"access_token":"dev"}}');

    await expect(operatorCodexAuth({ env: {}, home, runtime: undefined })).resolves.toContain('dev');
    await expect(operatorCodexAuth({ env: {}, home, runtime: 'k8s' })).resolves.toBeNull();
  });
});
