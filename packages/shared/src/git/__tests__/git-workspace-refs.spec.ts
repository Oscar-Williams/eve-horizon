import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { GitWorkspace, assertSafeGitRef } from '../git-workspace.js';

/**
 * A ref from a job's git config reaches git only as a ref: one that starts
 * with "-" or fails `git check-ref-format --allow-onelevel` is refused before
 * any git command runs, and fetch and checkout end their options before it.
 */
const created: string[] = [];

function git(cwd: string, ...args: string[]): void {
  execFileSync('git', args, {
    cwd,
    env: { ...process.env, GIT_CONFIG_GLOBAL: '/dev/null', GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t' },
    stdio: 'ignore',
  });
}

async function tmp(prefix: string): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), prefix));
  created.push(dir);
  return dir;
}

afterEach(async () => {
  await Promise.all(created.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

async function workspace(): Promise<GitWorkspace> {
  const source = await tmp('eve-git-refs-src-');
  git(source, 'init', '-q', '-b', 'main');
  await fs.writeFile(path.join(source, 'README.md'), 'hello\n');
  git(source, 'add', '.');
  git(source, 'commit', '-q', '-m', 'init');
  const ws = new GitWorkspace({
    repoUrl: `file://${source}`,
    workspacePath: await tmp('eve-git-refs-ws-'),
    gitUser: { name: 'Eve Bot', email: 'eve@example.com' },
    defaultBranch: 'main',
  });
  await ws.init('main');
  return ws;
}

describe('git refs from job config', () => {
  it('refuses option-like and malformed refs', async () => {
    await expect(assertSafeGitRef('--upload-pack=touch /tmp/x')).rejects.toThrow(/invalid git ref/);
    await expect(assertSafeGitRef('-b')).rejects.toThrow(/invalid git ref/);
    await expect(assertSafeGitRef('main..other')).rejects.toThrow(/invalid git ref/);
    await expect(assertSafeGitRef('')).rejects.toThrow(/invalid git ref/);
    await expect(assertSafeGitRef('main')).resolves.toBeUndefined();
    await expect(assertSafeGitRef('feature/shop-1')).resolves.toBeUndefined();
    await expect(assertSafeGitRef('0123456789abcdef0123456789abcdef01234567')).resolves.toBeUndefined();
  });

  it('runs no git command for a refused ref', async () => {
    const ws = await workspace();
    const runGit = vi.spyOn(ws, 'runGit');
    await expect(ws.checkout('--upload-pack=x')).rejects.toThrow(/invalid git ref/);
    await expect(ws.createBranch('--force', 'main', 'if_missing')).rejects.toThrow(/invalid git ref/);
    await expect(ws.createBranch('shop-1', '--orphan=x', 'if_missing')).rejects.toThrow(/invalid git ref/);
    expect(runGit).not.toHaveBeenCalled();
  });

  it('ends options before the ref it fetches, then checks out the checked ref', async () => {
    const ws = await workspace();
    const runGit = vi.spyOn(ws, 'runGit');
    await ws.checkout('main');
    const calls = runGit.mock.calls.map(([args]) => args);
    expect(calls).toContainEqual(['fetch', 'origin', '--end-of-options', 'main']);
    expect(calls).toContainEqual(['checkout', 'main']);
  });
});
