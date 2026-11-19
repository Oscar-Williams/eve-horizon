/**
 * Migrations from 00114 on that alter an existing table set a lock timeout
 * first, so their ALTER fails fast instead of queueing behind a long
 * transaction and blocking every query on the table behind it. The runner
 * applies each migration in its own transaction, so SET LOCAL holds for the
 * migration only.
 */

import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync } from 'fs';
import { dirname, join } from 'path';
import { fileURLToPath } from 'url';

const migrationsDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'migrations');
const FIRST = 114;

describe('migration lock timeouts', () => {
  const altering = readdirSync(migrationsDir)
    .filter((file) => /^\d{5}_.*\.sql$/.test(file) && Number(file.slice(0, 5)) >= FIRST)
    .filter((file) => /\bALTER\s+TABLE\b/i.test(readFileSync(join(migrationsDir, file), 'utf-8')));

  it('finds the migrations it covers', () => {
    expect(altering.length).toBeGreaterThan(0);
  });

  it.each(altering)('%s sets a lock timeout before it alters a table', (file) => {
    const sql = readFileSync(join(migrationsDir, file), 'utf-8');
    const setAt = sql.search(/\bSET\s+LOCAL\s+lock_timeout\b/i);
    expect(setAt).toBeGreaterThanOrEqual(0);
    expect(setAt).toBeLessThan(sql.search(/\bALTER\s+TABLE\b/i));
  });
});
