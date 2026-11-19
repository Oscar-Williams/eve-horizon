/**
 * OAuth states against a migrated database: a state is stored with its
 * expiry and the user (or install cookie) it is bound to; the callback
 * records the code once; completion consumes the state only for its owner,
 * only once, and only before it expires.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import postgres from 'postgres';
import { oauthStateQueries } from './integrations.js';
import type { Db } from '../client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 8);
const org = `org_acme${suffix}`;
const soon = () => new Date(Date.now() + 10 * 60 * 1000);

describe('oauth states', () => {
  let db: Db;

  beforeAll(async () => {
    db = postgres(testDbUrl!, { max: 2 }) as unknown as Db;
    await db`INSERT INTO orgs (id, name, slug) VALUES (${org}, ${org}, ${`acme${suffix}`})`;
  });

  afterAll(async () => {
    await db`DELETE FROM oauth_states WHERE org_id = ${org}`;
    await db`DELETE FROM orgs WHERE id = ${org}`;
    await (db as unknown as { end: () => Promise<void> }).end();
  });

  it('records the code once and lets only the user who started it consume the state, once', async () => {
    const states = oauthStateQueries(db);
    const id = `user-state-${suffix}`;
    await states.create({ id, provider: 'slack', org_id: org, user_id: 'user_alice', install_binding: null, expires_at: soon() });

    expect(await states.consumeForUser(id, 'user_alice')).toBeUndefined();
    expect(await states.recordCode(id, 'code-1')).toBe(true);
    expect(await states.recordCode(id, 'code-2')).toBe(false);
    expect(await states.consumeForUser(id, 'user_bob')).toBeUndefined();

    const consumed = await states.consumeForUser(id, 'user_alice');
    expect(consumed).toMatchObject({ org_id: org, provider: 'slack', code: 'code-1' });
    expect(await states.consumeForUser(id, 'user_alice')).toBeUndefined();
    expect(await states.find(id)).toBeUndefined();
  });

  it('lets an install state be consumed only with its cookie binding', async () => {
    const states = oauthStateQueries(db);
    const id = `install-state-${suffix}`;
    await states.create({ id, provider: 'slack', org_id: org, user_id: null, install_binding: 'binding-1', expires_at: soon() });

    expect(await states.consumeForInstall(id, 'binding-2')).toBeUndefined();
    expect(await states.consumeForInstall(id, 'binding-1')).toMatchObject({ org_id: org });
    expect(await states.consumeForInstall(id, 'binding-1')).toBeUndefined();
  });

  it('refuses a state bound to nobody', async () => {
    await expect(oauthStateQueries(db).create({
      id: `unbound-${suffix}`, provider: 'slack', org_id: org, user_id: null, install_binding: null, expires_at: soon(),
    })).rejects.toThrow();
  });

  it('does nothing with an expired state, and clears expired states', async () => {
    const states = oauthStateQueries(db);
    const id = `expired-state-${suffix}`;
    await states.create({
      id, provider: 'google_drive', org_id: org, user_id: 'user_alice', install_binding: null,
      expires_at: new Date(Date.now() - 1000),
    });

    expect(await states.recordCode(id, 'code-1')).toBe(false);
    expect(await states.consumeForUser(id, 'user_alice')).toBeUndefined();
    await states.deleteExpired();
    expect(await states.find(id)).toBeUndefined();
  });
});
