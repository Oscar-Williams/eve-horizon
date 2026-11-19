/**
 * The storage queries behind `eve system secrets reencrypt`, against a
 * migrated database: rows are listed by format, and each swap is a
 * compare-and-set on the stored value, so a row changed in between keeps its
 * new value.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import postgres from 'postgres';
import { secretQueries } from './secrets.js';
import { integrationQueries } from './integrations.js';
import { oauthAppConfigQueries } from './oauth-app-configs.js';
import type { Db } from '../client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 8);
const org = `org_acme${suffix}`;
const scope = `proj_shop${suffix}`;
const IV = 'AAAAAAAAAAAAAAAA';
const TAG = 'AAAAAAAAAAAAAAAAAAAAAA==';
const sealed = (data: string) => `v2:${IV}:${TAG}:${data}`;

describe('secret storage queries', () => {
  let db: Db;

  beforeAll(async () => {
    db = postgres(testDbUrl!, { max: 2 }) as unknown as Db;
    await db`INSERT INTO orgs (id, name, slug) VALUES (${org}, ${org}, ${`acme${suffix}`})`;
    await db`
      INSERT INTO secrets (id, scope_type, scope_id, key, type, value_encrypted) VALUES
        (${`secr_a${suffix}`}, 'project', ${scope}, 'A', 'env_var', 'v1:x:y:a'),
        (${`secr_b${suffix}`}, 'project', ${scope}, 'B', 'env_var', 'v1:x:y:b'),
        (${`secr_c${suffix}`}, 'project', ${scope}, 'C', 'env_var', ${sealed('c')})
    `;
    await db`
      INSERT INTO integrations (id, org_id, provider, account_id, tokens_json, status) VALUES
        (${`int_a${suffix}`}, ${org}, 'slack', ${`TA${suffix}`}, ${db.json({ access_token: 'xoxb-a', n: 1 } as never)}, 'active'),
        (${`int_b${suffix}`}, ${org}, 'slack', ${`TB${suffix}`}, ${db.json(sealed('b') as never)}, 'active'),
        (${`int_c${suffix}`}, ${org}, 'slack', ${`TC${suffix}`}, NULL, 'inactive')
    `;
    await db`
      INSERT INTO oauth_app_configs (id, org_id, provider, client_id, client_secret) VALUES
        (${`oac_a${suffix}`}, ${org}, 'slack', 'client-a', 'plain-secret'),
        (${`oac_b${suffix}`}, ${org}, 'google_drive', 'client-b', ${sealed('b')})
    `;
  });

  afterAll(async () => {
    await db`DELETE FROM secrets WHERE scope_id = ${scope}`;
    await db`DELETE FROM integrations WHERE org_id = ${org}`;
    await db`DELETE FROM oauth_app_configs WHERE org_id = ${org}`;
    await db`DELETE FROM orgs WHERE id = ${org}`;
    await (db as unknown as { end: () => Promise<void> }).end();
  });

  it('lists secrets in a format after a cursor, in id order', async () => {
    const secrets = secretQueries(db);
    const first = await secrets.listInFormat('v1', `secr_a${suffix}`.slice(0, -1), 1);
    expect(first.map((r) => r.key)).toEqual(['A']);
    const next = await secrets.listInFormat('v1', first[0].id, 10);
    expect(next.filter((r) => r.scope_id === scope).map((r) => r.key)).toEqual(['B']);
    const counts = await secrets.countByFormat();
    expect(counts.v1).toBeGreaterThanOrEqual(2);
    expect(counts.v2).toBeGreaterThanOrEqual(1);
  });

  it('swaps a secret ciphertext only while it still holds the value read', async () => {
    const secrets = secretQueries(db);
    expect(await secrets.swapCiphertext(`secr_a${suffix}`, 'v1:x:y:stale', sealed('a'))).toBe(false);
    expect((await secrets.findByScopeAndKey('project', scope, 'A'))?.value_encrypted).toBe('v1:x:y:a');
    expect(await secrets.swapCiphertext(`secr_a${suffix}`, 'v1:x:y:a', sealed('a'))).toBe(true);
    expect((await secrets.findByScopeAndKey('project', scope, 'A'))?.value_encrypted).toBe(sealed('a'));
  });

  it('lists and counts plain integration tokens, and swaps them only while unchanged', async () => {
    const integrations = integrationQueries(db);
    const plain = (await integrations.listPlainTokens('', 1000)).filter((r) => r.id.endsWith(suffix));
    expect(plain.map((r) => r.id)).toEqual([`int_a${suffix}`]);
    const counts = await integrations.countTokenFormats();
    expect(counts.plain).toBeGreaterThanOrEqual(1);
    expect(counts.sealed).toBeGreaterThanOrEqual(1);

    expect(await integrations.swapTokens(`int_a${suffix}`, { access_token: 'xoxb-old', n: 1 }, sealed('a'))).toBe(false);
    expect(await integrations.swapTokens(`int_a${suffix}`, { n: 1, access_token: 'xoxb-a' }, sealed('a'))).toBe(true);
    expect((await integrations.findById(`int_a${suffix}`))?.tokens_json).toBe(sealed('a'));
  });

  it('lists the active integrations', async () => {
    const active = (await integrationQueries(db).listActive()).filter((r) => r.org_id === org);
    expect(active.map((r) => r.id).sort()).toEqual([`int_a${suffix}`, `int_b${suffix}`]);
  });

  it('treats only a whole v2 envelope as a sealed client secret, and swaps only while unchanged', async () => {
    await db`UPDATE oauth_app_configs SET client_secret = 'v2:looks-like-a-prefix' WHERE id = ${`oac_a${suffix}`}`;
    const configs = oauthAppConfigQueries(db);
    const plain = (await configs.listPlainClientSecrets('', 1000)).filter((r) => r.id.endsWith(suffix));
    expect(plain).toEqual([{ id: `oac_a${suffix}`, client_secret: 'v2:looks-like-a-prefix' }]);
    const counts = await configs.countClientSecretFormats();
    expect(counts.sealed).toBeGreaterThanOrEqual(1);

    expect(await configs.swapClientSecret(`oac_a${suffix}`, 'plain-secret', sealed('a'))).toBe(false);
    expect(await configs.swapClientSecret(`oac_a${suffix}`, 'v2:looks-like-a-prefix', sealed('a'))).toBe(true);
    expect((await configs.findByOrgAndProvider(org, 'slack'))?.client_secret).toBe(sealed('a'));
  });
});
