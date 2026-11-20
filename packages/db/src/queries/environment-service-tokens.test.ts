/**
 * An environment's service tokens can be revoked: `service_tokens_not_before`
 * is null until a rotation sets it, and a later rotation never moves it back.
 */

import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import postgres from 'postgres';
import { environmentQueries } from './environments.js';
import type { Db } from '../client.js';

const testDbUrl = process.env.TEST_DATABASE_URL || process.env.DATABASE_URL;

if (!testDbUrl) {
  throw new Error('TEST_DATABASE_URL or DATABASE_URL environment variable is required for tests');
}

const suffix = Math.random().toString(36).slice(2, 8);
const org = `org_acme${suffix}`;
const project = `proj_shop${suffix}`;
const env = `env_prod${suffix}`;

describe('environment service tokens', () => {
  let db: Db;

  beforeAll(async () => {
    db = postgres(testDbUrl!, { max: 2 }) as unknown as Db;
    await db`INSERT INTO orgs (id, name, slug) VALUES (${org}, ${org}, ${`a${suffix}`})`;
    await db`INSERT INTO projects (id, org_id, name, slug, repo_url)
             VALUES (${project}, ${org}, ${project}, ${`s${suffix}`}, 'https://example.com/shop.git')`;
    await db`INSERT INTO environments (id, project_id, name, type) VALUES (${env}, ${project}, 'prod', 'persistent')`;
  });

  afterAll(async () => {
    await db`DELETE FROM environments WHERE project_id = ${project}`;
    await db`DELETE FROM projects WHERE id = ${project}`;
    await db`DELETE FROM orgs WHERE id = ${org}`;
    await (db as unknown as { end: () => Promise<void> }).end();
  });

  it('has no floor until a rotation', async () => {
    const row = await environmentQueries(db).findById(env);
    expect(row?.service_tokens_not_before).toBeNull();
  });

  it('sets the floor on a rotation and never moves it back', async () => {
    const environments = environmentQueries(db);
    const first = new Date('2026-11-20T12:00:00Z');

    const rotated = await environments.revokeServiceTokens(env, first);
    expect(rotated?.service_tokens_not_before?.toISOString()).toBe(first.toISOString());

    const back = await environments.revokeServiceTokens(env, new Date('2026-11-20T11:00:00Z'));
    expect(back?.service_tokens_not_before?.toISOString()).toBe(first.toISOString());

    const later = new Date('2026-11-20T13:00:00Z');
    expect((await environments.revokeServiceTokens(env, later))?.service_tokens_not_before?.toISOString())
      .toBe(later.toISOString());
  });

  it('finds no environment to rotate when it is gone', async () => {
    expect(await environmentQueries(db).revokeServiceTokens(`env_gone${suffix}`, new Date())).toBeNull();
  });
});
