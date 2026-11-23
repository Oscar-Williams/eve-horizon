import { afterEach, describe, expect, it } from 'vitest';
import {
  getManagedDbExtensionValidationError,
  getSupportedExtensionDefinition,
  normalizeManagedDbExtensions,
  parseEnabledPreloadExtensions,
  quotePostgresIdentifier,
  sharedPreloadLibrariesContains,
} from '../extensions.js';

describe('managed DB extension registry', () => {
  it('normalizes requested extensions into allowlist order', () => {
    expect(normalizeManagedDbExtensions(['pg_trgm', 'postgis', 'pgvector'])).toEqual([
      'postgis',
      'pgvector',
      'pg_trgm',
    ]);
  });

  it('maps manifest names to canonical Postgres extension names', () => {
    expect(getSupportedExtensionDefinition('pgvector')).toMatchObject({
      extname: 'vector',
    });
    expect(getSupportedExtensionDefinition('pg_cron')).toMatchObject({
      mode: 'preload',
      extname: 'pg_cron',
      preloadName: 'pg_cron',
      installScope: 'instance_admin_db',
    });
    expect(getSupportedExtensionDefinition('postgis')).toMatchObject({
      extname: 'postgis',
    });
  });

  it('requires explicit provider gating for preload extensions', () => {
    expect(() => normalizeManagedDbExtensions(['pg_cron'])).toThrow(/provider preload support/i);
    expect(normalizeManagedDbExtensions(['pg_cron'], {
      enabledPreloadExtensions: ['pg_cron'],
    })).toEqual(['pg_cron']);
  });

  it('parses enabled preload extensions from comma-separated config', () => {
    expect(parseEnabledPreloadExtensions(undefined)).toEqual([]);
    expect(parseEnabledPreloadExtensions('pg_cron,unknown')).toEqual(['pg_cron']);
    expect(parseEnabledPreloadExtensions('*')).toEqual(['pg_cron']);
  });

  it('checks shared_preload_libraries exactly', () => {
    expect(sharedPreloadLibrariesContains('pg_stat_statements, pg_cron', 'pg_cron')).toBe(true);
    expect(sharedPreloadLibrariesContains('pg_cron_extra', 'pg_cron')).toBe(false);
    expect(sharedPreloadLibrariesContains('', 'pg_cron')).toBe(false);
  });

  it('quotes Postgres identifiers safely', () => {
    expect(quotePostgresIdentifier('postgis')).toBe('"postgis"');
    expect(quotePostgresIdentifier('weird"name')).toBe('"weird""name"');
  });
});

/**
 * Eve installs a tenant's extensions as its platform login, inside the
 * tenant's own database, into "public", which the tenant can write. An
 * extension PostgreSQL does not mark trusted has an install script nobody
 * vouches for in that setting, so it is refused unless the platform opts in.
 */
describe('extensions PostgreSQL does not mark trusted', () => {
  const OPT_IN = 'EVE_MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS';

  afterEach(() => {
    delete process.env[OPT_IN];
  });

  it('refuses postgis and pgvector, naming the opt-in', () => {
    for (const extension of ['postgis', 'pgvector']) {
      const error = getManagedDbExtensionValidationError(extension);
      expect(error).toMatch(/not marked trusted/);
      expect(error).toContain(`${OPT_IN}=true`);
    }
  });

  it('accepts the trusted core extensions as before', () => {
    for (const extension of ['pg_trgm', 'btree_gist', 'hstore', 'citext']) {
      expect(getManagedDbExtensionValidationError(extension)).toBeNull();
    }
  });

  it('accepts untrusted extensions only when the opt-in is exactly "true"', () => {
    for (const value of ['1', 'yes', 'TRUE ', '']) {
      process.env[OPT_IN] = value;
      expect(getManagedDbExtensionValidationError('postgis')).toMatch(/not marked trusted/);
    }

    process.env[OPT_IN] = 'true';
    expect(getManagedDbExtensionValidationError('postgis')).toBeNull();
    expect(getManagedDbExtensionValidationError('pgvector')).toBeNull();
  });
});
