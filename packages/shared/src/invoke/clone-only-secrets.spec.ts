import { describe, expect, it } from 'vitest';
import type { HarnessInvocation } from '../types/harness.js';
import { selectJobSecrets } from './secrets-allowlist.js';
import { assertCloneOnlyGitCredentialSafe, prepareGitAuth } from './workspace-secrets.js';

/**
 * A secret the server flags clone_only is the platform's credential for the
 * workspace clone. It is used for the clone and nothing else: the harness
 * never receives it, it never lands in the clone URL (and so in
 * .git/config), and a job that would need it after the clone is refused.
 */
const invocation = {
  jobId: 'shop-1',
  attemptId: 'att-clone-only',
  projectId: 'proj_shop',
  text: '',
  repoUrl: 'https://github.com/acme/shop.git',
  workspacePath: '/nonexistent/eve-clone-only',
} as unknown as HarnessInvocation;

const secrets = [
  { key: 'ANTHROPIC_API_KEY', value: 'sk-org', type: 'env_var' as const },
  { key: 'GITHUB_TOKEN', value: 'ghp_shop', type: 'github_token' as const, clone_only: true },
];

describe('clone-only credentials', () => {
  it('never reach the harness', async () => {
    expect((await selectJobSecrets(invocation, secrets)).map((s) => s.key)).toEqual(['ANTHROPIC_API_KEY']);
  });

  it('travel as a header for the platform git calls, not in the clone URL', async () => {
    const auth = await prepareGitAuth(invocation, secrets);
    expect(auth?.cloneUrl).toBeUndefined();
    expect(JSON.stringify(auth?.env)).not.toContain('ghp_shop');
    expect(auth?.env?.GIT_CONFIG_KEY_0).toBe('http.https://github.com/.extraheader');
  });

  it('refuse a job that would push with them', async () => {
    await expect(assertCloneOnlyGitCredentialSafe({ ...invocation, git: { push: 'on_success' } } as never, secrets))
      .rejects.toThrow(/git_credential_not_allowlisted/);
    await expect(assertCloneOnlyGitCredentialSafe(invocation, secrets)).resolves.toBeUndefined();
  });
});
