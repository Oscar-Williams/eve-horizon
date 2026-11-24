import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { mkdtemp, mkdir, writeFile, readFile, rm, stat, symlink } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { BuildKitBuilder, resolveIsolatedCacheRepo } from '../buildkit-builder.js';
import type { BuildServiceParams } from '../image-builder.interface.js';
let dir: string;
let params: BuildServiceParams;
const digest = `sha256:${'a'.repeat(64)}`;

// Resolve the test executable explicitly: Linux deliberately removes writable
// directories from serviceHelperEnv's PATH. Keep the real subprocess and env.
const fixture = vi.hoisted(() => ({ buildctl: '' }));
vi.mock('node:child_process', async (importOriginal) => {
  const actual = await importOriginal<typeof import('node:child_process')>();
  return {
    ...actual,
    spawn: (command: string, args: readonly string[], options: import('node:child_process').SpawnOptionsWithoutStdio) =>
      actual.spawn(command === 'buildctl' ? fixture.buildctl : command, args, options),
  };
});

beforeEach(async () => {
  dir = await mkdtemp(join(tmpdir(), 'buildkit-session-test-'));
  params = { projectId: 'proj_shop', serviceName: 'web', service: { build: { context: '.' } },
    registryAuth: { host: 'registry.example.com', username: 'test', token: 'test', dockerConfigJson: Buffer.from('{"auths":{}}').toString('base64') },
    registryConfig: { host: 'registry.example.com' }, gitSha: 'abc', workspacePath: dir,
    imageRef: 'registry.example.com/shop/web', tag: 'test' };
  await writeFile(join(dir, 'Dockerfile'), 'FROM scratch\n');
  fixture.buildctl = join(dir, 'buildctl');
  vi.stubEnv('EVE_INTERNAL_API_KEY', 'must-not-reach-client');
  await writeFile(fixture.buildctl, `#!${process.execPath}
const fs = require('node:fs');
const args = process.argv.slice(2);
const context = args.find(a => a.startsWith('context=')).slice(8);
fs.writeFileSync('session.json', JSON.stringify({ args, configDir: process.env.DOCKER_CONFIG,
  gitMetadataPresent: fs.existsSync(context + '/.git'),
  dockerfileLink: fs.existsSync(context + '/Dockerfile.alias') ? fs.readlinkSync(context + '/Dockerfile.alias') : null,
  context,
  mode: fs.statSync(process.env.DOCKER_CONFIG + '/config.json').mode & 511,
  config: JSON.parse(fs.readFileSync(process.env.DOCKER_CONFIG + '/config.json')),
  platformKeyPresent: !!process.env.EVE_INTERNAL_API_KEY }));
if (fs.existsSync('wait')) { setInterval(() => {}, 100); }
else if (fs.existsSync('fail')) { process.exit(42); }
else { fs.writeFileSync(args[args.indexOf('--metadata-file') + 1], JSON.stringify({ 'containerimage.digest': '${digest}' })); }
`, { mode: 0o700 });
});
afterEach(async () => { vi.unstubAllEnvs(); await rm(dir, { recursive: true, force: true }); });

async function assertSessionCleaned() {
  const session = JSON.parse(await readFile(join(dir, 'session.json'), 'utf8'));
  expect(session.mode).toBe(0o600);
  expect(session.config).toEqual({ auths: {} });
  expect(session.platformKeyPresent).toBe(false);
  await expect(stat(session.configDir)).rejects.toMatchObject({ code: 'ENOENT' });
  return session;
}

describe('BuildKit client session', () => {
  it('uses only the supplied endpoint and removes its private auth config after success', async () => {
    vi.stubEnv('EVE_BUILDKIT_ADDR', 'tcp://shared:1234');
    await expect(new BuildKitBuilder().buildServiceAt(params, 'tcp://10.10.0.2:1234', true)).resolves.toBe(digest);
    const session = await assertSessionCleaned();
    expect(session.args.slice(0, 2)).toEqual(['--addr', 'tcp://10.10.0.2:1234']);
  });

  it('excludes credential-bearing checkout metadata from the context snapshot', async () => {
    await mkdir(join(dir, '.git'));
    await writeFile(join(dir, '.git', 'config'), 'dummy-clone-credential');
    await new BuildKitBuilder().buildServiceAt(params, 'tcp://10.10.0.2:1234', true);
    const session = await assertSessionCleaned();
    expect(session.gitMetadataPresent).toBe(false);
    expect(session.context).not.toBe(dir);
    await expect(stat(session.context)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('preserves a relative Dockerfile symlink when moving the context snapshot', async () => {
    await symlink('Dockerfile', join(dir, 'Dockerfile.alias'));
    params.service.build = { context: '.', dockerfile: 'Dockerfile.alias' };
    await new BuildKitBuilder().buildServiceAt(params, 'tcp://10.10.0.2:1234', true);
    const session = await assertSessionCleaned();
    expect(session.dockerfileLink).toBe('Dockerfile');
  });

  it('refuses a build context outside the checkout', async () => {
    params.service.build = { context: '..' };
    await expect(new BuildKitBuilder().buildServiceAt(params, 'tcp://10.10.0.2:1234', true)).rejects.toThrow('outside');
  });

  it('refuses a Dockerfile symlink outside the context', async () => {
    await symlink('/etc/hosts', join(dir, 'outside.Dockerfile'));
    params.service.build = { context: '.', dockerfile: 'outside.Dockerfile' };
    await expect(new BuildKitBuilder().buildServiceAt(params, 'tcp://10.10.0.2:1234', true)).rejects.toThrow('outside');
  });

  it('removes private auth config on client failure', async () => {
    await writeFile(join(dir, 'fail'), '');
    await expect(new BuildKitBuilder().buildServiceAt(params, 'tcp://10.10.0.2:1234', true)).rejects.toThrow('exit code 42');
    await assertSessionCleaned();
  });

  it('terminates a running client and removes private auth config on cancellation', async () => {
    await writeFile(join(dir, 'wait'), '');
    const controller = new AbortController();
    const result = expect(new BuildKitBuilder().buildServiceAt({ ...params, signal: controller.signal }, 'tcp://10.10.0.2:1234', true)).rejects.toThrow('cancelled');
    for (let n = 0; n < 100; n++) {
      if (await stat(join(dir, 'session.json')).then(() => true, () => false)) break;
      await new Promise((r) => setTimeout(r, 20));
    }
    controller.abort(new Error('cancelled'));
    await result;
    await assertSessionCleaned();
  }, 10_000);

  it('separates an external registry cache by project in the authorized image repository', () => {
    const other = { ...params, projectId: 'proj_other' };
    expect(resolveIsolatedCacheRepo('ghcr.io/shared/cache', params)).toBe(`${params.imageRef}:eve-cache-proj_shop`);
    expect(resolveIsolatedCacheRepo('ghcr.io/shared/cache', other)).not.toBe(resolveIsolatedCacheRepo('ghcr.io/shared/cache', params));
    expect(resolveIsolatedCacheRepo(undefined, params)).toBeUndefined();
  });
});
