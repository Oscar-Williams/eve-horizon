import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { HarnessInvocation } from '../../types/harness.js';
import type { SecretResolveItem } from '../../schemas/secret.js';
import {
  cleanupJobSecretArtifacts,
  materializeSecrets,
  prepareGitAuth,
} from '../workspace-secrets.js';

const created: string[] = [];

async function makeWorkspace(): Promise<string> {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-job-secrets-test-'));
  created.push(dir);
  return dir;
}

function invocationFor(workspacePath: string, attemptId: string): HarnessInvocation {
  return {
    attemptId,
    jobId: 'proj-a1b2c3d4',
    projectId: 'proj_test',
    text: 'prompt',
    workspacePath,
    repoUrl: 'git@github.com:org/repo.git',
  } as HarnessInvocation;
}

function secret(key: string, value: string, type: SecretResolveItem['type']): SecretResolveItem {
  return { key, value, type, scope_type: 'project', scope_id: 'proj_test' } as SecretResolveItem;
}

async function exists(target: string): Promise<boolean> {
  return fs.stat(target).then(() => true, () => false);
}

afterEach(async () => {
  await Promise.all(created.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

describe('cleanupJobSecretArtifacts', () => {
  it('removes the file secrets materialized for the attempt', async () => {
    const workspace = await makeWorkspace();
    const attemptId = `att-${path.basename(workspace)}`;
    const invocation = invocationFor(workspace, attemptId);

    const { env } = await materializeSecrets(path.join(workspace, 'repo'), invocation, [
      secret('SERVICE_ACCOUNT_JSON', '{"private_key":"x"}', 'file'),
    ], null);
    const filePath = env.SERVICE_ACCOUNT_JSON as string;
    expect(await exists(filePath)).toBe(true);

    await cleanupJobSecretArtifacts(invocation);

    expect(await exists(filePath)).toBe(false);
    expect(await exists(path.dirname(filePath))).toBe(false);
  });

  it('removes the git SSH key written for the workspace clone', async () => {
    const workspace = await makeWorkspace();
    const invocation = invocationFor(workspace, `att-${path.basename(workspace)}`);

    await prepareGitAuth(invocation, [secret('DEPLOY_KEY', 'ssh-key-material', 'ssh_key')]);
    const keyPath = path.join(workspace, '.eve', 'git_ssh_key');
    expect(await exists(keyPath)).toBe(true);

    await cleanupJobSecretArtifacts(invocation);

    expect(await exists(keyPath)).toBe(false);
  });

  it('removes the worker git SSH key folder for the attempt', async () => {
    const workspace = await makeWorkspace();
    const attemptId = `att-${path.basename(workspace)}`;
    const keyDir = path.join(os.tmpdir(), 'eve', 'worker-secrets', attemptId);
    await fs.mkdir(keyDir, { recursive: true });
    await fs.writeFile(path.join(keyDir, 'git_ssh_key'), 'ssh-key-material');

    await cleanupJobSecretArtifacts(invocationFor(workspace, attemptId));

    expect(await exists(keyDir)).toBe(false);
  });

  it('leaves another attempt\'s secret files in place', async () => {
    const workspace = await makeWorkspace();
    const mine = invocationFor(workspace, `att-mine-${path.basename(workspace)}`);
    const other = invocationFor(workspace, `att-other-${path.basename(workspace)}`);
    const { env } = await materializeSecrets(path.join(workspace, 'repo'), other, [
      secret('OTHER_FILE', 'other', 'file'),
    ], null);

    await cleanupJobSecretArtifacts(mine);

    expect(await exists(env.OTHER_FILE as string)).toBe(true);
    await cleanupJobSecretArtifacts(other);
  });

  it('refuses an attempt id that would escape the secrets folder', async () => {
    const workspace = await makeWorkspace();
    const sibling = path.join(os.tmpdir(), 'eve', `keep-${path.basename(workspace)}`);
    await fs.mkdir(sibling, { recursive: true });
    created.push(sibling);

    await cleanupJobSecretArtifacts(invocationFor(workspace, `../keep-${path.basename(workspace)}`));

    expect(await exists(sibling)).toBe(true);
  });
});
