import { describe, expect, it } from 'vitest';
import { generateManagedDbName, generateManagedDbUser } from '../managed-db/index.js';

// A new environment that reuses an old one's name must not get the old
// database's name: if the old database is still waiting to be dropped, the
// new environment would attach to it.

describe('managed database names', () => {
  it('differ for two environments with the same name', () => {
    expect(generateManagedDbName('acme', 'shop', 'test', 'env_01aaa'))
      .not.toBe(generateManagedDbName('acme', 'shop', 'test', 'env_01bbb'));
    expect(generateManagedDbUser('acme', 'shop', 'test', 'env_01aaa'))
      .not.toBe(generateManagedDbUser('acme', 'shop', 'test', 'env_01bbb'));
  });

  it('keep the old form without an environment id', () => {
    expect(generateManagedDbName('acme', 'shop', 'test')).toMatch(/^acme-shop-test-[0-9a-f]{6}$/);
    expect(generateManagedDbUser('acme', 'shop', 'test')).toMatch(/^acme-shop-test-u-[0-9a-f]{6}$/);
  });
});
