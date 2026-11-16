import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { GitWorkspace } from '../git-workspace.js';

const SENTINEL = 'c2VudGluZWwtdG9rZW4tZG8tbm90LWxlYWs';
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

describe('GitWorkspace credential env', () => {
  it("never hands the clone credential to a filter driver the job wrote into the repo's config", async () => {
    const source = await tmp('eve-git-src-');
    git(source, 'init', '-q', '-b', 'main');
    await fs.writeFile(path.join(source, 'README.md'), 'hello\n');
    git(source, 'add', '.');
    git(source, 'commit', '-q', '-m', 'init');

    const workspacePath = await tmp('eve-git-ws-');
    const workspace = new GitWorkspace({
      repoUrl: `file://${source}`,
      workspacePath,
      // What prepareGitAuth returns for a token a secrets allowlist leaves out.
      gitAuth: {
        env: {
          GIT_CONFIG_COUNT: '1',
          GIT_CONFIG_KEY_0: 'http.https://github.com/.extraheader',
          GIT_CONFIG_VALUE_0: `AUTHORIZATION: basic ${SENTINEL}`,
          GIT_SSH_COMMAND: 'ssh -i /tmp/eve-sentinel-key',
        },
      },
      gitConfig: { commit: 'auto', push: 'never' },
      gitUser: { name: 'Eve Bot', email: 'eve@example.com' },
      defaultBranch: 'main',
    });
    await workspace.init('main');
    await workspace.checkout('main');

    // The harness, which runs as the same user, plants a clean filter that dumps its env.
    const repo = path.join(workspacePath, 'repo');
    const leak = path.join(workspacePath, 'leak.txt');
    git(repo, 'config', 'filter.leak.clean', `sh -c 'env >> ${leak}; cat'`);
    await fs.writeFile(path.join(repo, '.gitattributes'), '* filter=leak\n');
    await fs.writeFile(path.join(repo, 'notes.md'), 'agent output\n');

    // The platform's commit policy then stages and commits the agent's work.
    await workspace.commit('agent output');

    const dumped = await fs.readFile(leak, 'utf8');
    expect(dumped.length).toBeGreaterThan(0);
    expect(dumped).not.toContain(SENTINEL);
    expect(dumped).not.toContain('eve-sentinel-key');
  });
});
