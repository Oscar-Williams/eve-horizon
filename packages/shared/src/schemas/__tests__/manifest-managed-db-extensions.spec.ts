import { afterEach, describe, expect, it } from 'vitest';
import { MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV } from '../../managed-db/extensions.js';
import { ManifestSchema } from '../manifest.js';

const ALLOW_UNTRUSTED = 'EVE_MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS';

function parseManifest(extensions: string[]) {
  return ManifestSchema.safeParse({
    schema: 'eve/compose/v2',
    services: {
      db: {
        'x-eve': {
          role: 'managed_db',
          managed: {
            class: 'db.p1',
            engine: 'postgres',
            extensions,
          },
        },
      },
    },
  });
}

describe('managed DB extension manifest schema', () => {
  afterEach(() => {
    delete process.env[MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV];
    delete process.env[ALLOW_UNTRUSTED];
  });

  it('accepts and normalizes supported extension names', () => {
    process.env[ALLOW_UNTRUSTED] = 'true';
    const parsed = parseManifest(['pg_trgm', 'postgis', 'pgvector']);

    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.services?.db?.['x-eve']?.managed?.extensions).toEqual([
      'postgis',
      'pgvector',
      'pg_trgm',
    ]);
  });

  it('rejects unknown extension names', () => {
    const parsed = parseManifest(['postgis', 'made_up_ext']);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.some((issue) => issue.path.includes('extensions'))).toBe(true);
  });

  it('rejects duplicate extension names', () => {
    const parsed = parseManifest(['postgis', 'postgis']);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.some((issue) => issue.message.includes('Duplicate managed DB extension'))).toBe(true);
  });

  it('rejects provider-gated preload extensions unless explicitly enabled', () => {
    const disabled = parseManifest(['pg_cron']);

    expect(disabled.success).toBe(false);
    if (disabled.success) return;
    expect(disabled.error.issues.some((issue) => issue.message.includes('provider preload support'))).toBe(true);

    process.env[MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV] = 'pg_cron';
    const enabled = parseManifest(['pg_cron']);

    expect(enabled.success).toBe(true);
    if (!enabled.success) return;
    expect(enabled.data.services?.db?.['x-eve']?.managed?.extensions).toEqual(['pg_cron']);
  });

  it('rejects preload candidates that do not have a provider model yet', () => {
    process.env[MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV] = '*';
    const parsed = parseManifest(['timescaledb']);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.some((issue) => issue.message.includes('preload candidate'))).toBe(true);
  });

  it('refuses extensions PostgreSQL does not mark trusted, saying why and how to opt in', () => {
    const parsed = parseManifest(['pg_trgm', 'postgis']);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    const messages = parsed.error.issues.map((issue) => issue.message);
    expect(messages).toHaveLength(1);
    expect(messages[0]).toContain('"postgis" is not marked trusted by PostgreSQL');
    expect(messages[0]).toContain(`${ALLOW_UNTRUSTED}=true`);
  });

  it('accepts trusted extensions without the opt-in', () => {
    const parsed = parseManifest(['citext', 'pg_trgm']);

    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.services?.db?.['x-eve']?.managed?.extensions).toEqual(['pg_trgm', 'citext']);
  });

  it('accepts untrusted extensions when the platform opts in', () => {
    process.env[ALLOW_UNTRUSTED] = 'true';
    const parsed = parseManifest(['pgvector']);

    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.services?.db?.['x-eve']?.managed?.extensions).toEqual(['pgvector']);
  });
});
