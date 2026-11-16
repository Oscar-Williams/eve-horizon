import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { HarnessInvocation } from '../../types/harness.js';
import type { SecretResolveItem } from '../../schemas/secret.js';
import { assertCloneOnlyGitCredentialSafe } from '../workspace-secrets.js';

const created: string[] = [];
afterEach(async () => {
  await Promise.all(created.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

async function invocation(overrides: Partial<HarnessInvocation> = {}): Promise<HarnessInvocation> {
  const workspacePath = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-clone-only-'));
  created.push(workspacePath);
  return {
    attemptId: 'att-1', jobId: 'opps-1', projectId: 'proj_opps', text: 'triage', workspacePath,
    repoUrl: 'https://github.com/org/repo.git', secrets_allowlist: ['ANTHROPIC_API_KEY'],
    ...overrides,
  } as HarnessInvocation;
}

const TOKEN: SecretResolveItem = { key: 'GITHUB_TOKEN', value: 'ghs_x', type: 'env_var', scope_type: 'project', scope_id: 'p' } as SecretResolveItem;
const SSH: SecretResolveItem = { key: 'DEPLOY_KEY', value: 'key', type: 'ssh_key', scope_type: 'project', scope_id: 'p' } as SecretResolveItem;

describe('a git credential the job may not hold', () => {
  it('is used for a fresh clone of a job that does not push', async () => {
    await expect(assertCloneOnlyGitCredentialSafe(await invocation({ git: { push: 'never' } as never }), [TOKEN])).resolves.toBeUndefined();
    await expect(assertCloneOnlyGitCredentialSafe(await invocation(), [TOKEN])).resolves.toBeUndefined();
  });

  it('is refused to a job whose git policy pushes, since the push would run under repo config the job wrote', async () => {
    for (const push of ['on_success', 'required']) {
      await expect(assertCloneOnlyGitCredentialSafe(await invocation({ git: { push } as never }), [TOKEN]))
        .rejects.toThrow(/secrets allowlist/);
    }
  });

  it('is refused to a reused workspace, whose repo config an earlier attempt could have written', async () => {
    await expect(assertCloneOnlyGitCredentialSafe(await invocation({ workspace: { mode: 'session' } as never }), [TOKEN]))
      .rejects.toThrow(/secrets allowlist/);

    const reused = await invocation();
    await fs.mkdir(path.join(reused.workspacePath, 'repo', '.git'), { recursive: true });
    await expect(assertCloneOnlyGitCredentialSafe(reused, [TOKEN]))
      .rejects.toThrow(/secrets allowlist/);
  });

  it('places no limit when the job may hold the credential or no allowlist applies', async () => {
    const pushing = { git: { push: 'required' } as never, workspace: { mode: 'session' } as never };
    await expect(assertCloneOnlyGitCredentialSafe(await invocation({ ...pushing, secrets_allowlist: ['GITHUB_TOKEN'] }), [TOKEN])).resolves.toBeUndefined();
    await expect(assertCloneOnlyGitCredentialSafe(await invocation({ ...pushing, secrets_allowlist: undefined }), [TOKEN])).resolves.toBeUndefined();
    await expect(assertCloneOnlyGitCredentialSafe(await invocation({ ...pushing }), [])).resolves.toBeUndefined();
  });

  it('applies to an SSH deploy key the same way', async () => {
    await expect(assertCloneOnlyGitCredentialSafe(
      await invocation({ repoUrl: 'git@github.com:org/repo.git', git: { push: 'on_success' } as never }), [SSH],
    )).rejects.toThrow(/secrets allowlist/);
  });

  it('places no limit for a non-GitHub HTTPS repo, where the GitHub token is never used', async () => {
    await expect(assertCloneOnlyGitCredentialSafe(
      await invocation({ repoUrl: 'https://gitlab.example.com/org/repo.git', git: { push: 'on_success' } as never }), [TOKEN],
    )).resolves.toBeUndefined();
  });
});
