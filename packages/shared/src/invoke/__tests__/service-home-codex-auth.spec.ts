import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { removeStaleServiceHomeCodexAuth } from '../codex-auth.js';

const created: string[] = [];
afterEach(async () => {
  await Promise.all(created.splice(0).map((dir) => fs.rm(dir, { recursive: true, force: true })));
});

async function serviceHomeWithStaleAuth(): Promise<string> {
  const home = await fs.mkdtemp(path.join(os.tmpdir(), 'eve-service-home-'));
  created.push(home);
  for (const dir of ['.codex', '.code']) {
    await fs.mkdir(path.join(home, dir), { recursive: true });
    await fs.writeFile(path.join(home, dir, 'auth.json'), '{"tokens":{"access_token":"left-by-a-job"}}');
    await fs.writeFile(path.join(home, dir, 'config.toml'), 'model = "x"\n');
  }
  return home;
}

async function exists(target: string): Promise<boolean> {
  return fs.stat(target).then(() => true, () => false);
}

describe('removeStaleServiceHomeCodexAuth', () => {
  it("removes the auth.json files earlier versions wrote into a k8s runtime's own HOME", async () => {
    const home = await serviceHomeWithStaleAuth();

    await removeStaleServiceHomeCodexAuth({ home, runtime: 'k8s' });

    expect(await exists(path.join(home, '.codex', 'auth.json'))).toBe(false);
    expect(await exists(path.join(home, '.code', 'auth.json'))).toBe(false);
    expect(await exists(path.join(home, '.codex', 'config.toml'))).toBe(true);
  });

  it("leaves a developer's own login alone when the services run locally", async () => {
    const home = await serviceHomeWithStaleAuth();

    await removeStaleServiceHomeCodexAuth({ home, runtime: undefined });

    expect(await exists(path.join(home, '.codex', 'auth.json'))).toBe(true);
  });
});
