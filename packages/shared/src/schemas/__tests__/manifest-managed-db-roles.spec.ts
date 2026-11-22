import { describe, expect, it } from 'vitest';
import { ManifestSchema } from '../manifest.js';

function parseManifest(roles?: unknown) {
  return ManifestSchema.safeParse({
    schema: 'eve/compose/v2',
    services: {
      db: {
        'x-eve': {
          role: 'managed_db',
          managed: {
            class: 'db.p1',
            engine: 'postgres',
            ...(roles === undefined ? {} : { roles }),
          },
        },
      },
    },
  });
}

describe('managed DB roles manifest schema', () => {
  it('defaults to no roles when the block is absent', () => {
    const parsed = parseManifest();

    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.services?.db?.['x-eve']?.managed?.roles).toEqual([]);
  });

  it('accepts readwrite and readonly roles', () => {
    const parsed = parseManifest([
      { name: 'app', grants: 'readwrite' },
      { name: 'reporting_ro', grants: 'readonly' },
    ]);

    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.services?.db?.['x-eve']?.managed?.roles).toEqual([
      { name: 'app', grants: 'readwrite' },
      { name: 'reporting_ro', grants: 'readonly' },
    ]);
  });

  it.each([
    ['uppercase', 'App'],
    ['leading digit', '1app'],
    ['hyphen', 'app-ro'],
    ['too long', 'a'.repeat(17)],
    ['empty', ''],
  ])('rejects role names with %s', (_label, name) => {
    const parsed = parseManifest([{ name, grants: 'readonly' }]);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.some((issue) => issue.path.includes('roles'))).toBe(true);
  });

  it('accepts a 16-character role name', () => {
    const parsed = parseManifest([{ name: 'a'.repeat(16), grants: 'readonly' }]);

    expect(parsed.success).toBe(true);
  });

  it('rejects unknown grants', () => {
    const parsed = parseManifest([{ name: 'app', grants: 'admin' }]);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.some((issue) => issue.path.includes('grants'))).toBe(true);
  });

  it('rejects duplicate role names', () => {
    const parsed = parseManifest([
      { name: 'app', grants: 'readwrite' },
      { name: 'app', grants: 'readonly' },
    ]);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.some((issue) => issue.message.includes('Duplicate managed DB role'))).toBe(true);
  });

  it('accepts up to 8 roles', () => {
    const roles = Array.from({ length: 8 }, (_, i) => ({ name: `role${i}`, grants: 'readonly' }));
    const parsed = parseManifest(roles);

    expect(parsed.success).toBe(true);
  });

  it('refuses more than 8 roles, each login holding its own connections', () => {
    const roles = Array.from({ length: 9 }, (_, i) => ({ name: `role${i}`, grants: 'readonly' }));
    const parsed = parseManifest(roles);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.map((issue) => issue.message)).toContain(
      'A managed database declares at most 8 roles (found 9)',
    );
  });
});

describe('schema-owner roles', () => {
  const owner = (schema: unknown, extra: Record<string, unknown> = {}) => ({
    name: 'gotrue',
    grants: { schema, owner: true, ...extra },
  });

  function messages(parsed: ReturnType<typeof parseManifest>): string[] {
    return parsed.success ? [] : parsed.error.issues.map((issue) => issue.message);
  }

  it('accepts a role that owns one named schema, beside readwrite roles', () => {
    const parsed = parseManifest([
      { name: 'app', grants: 'readwrite' },
      owner('auth'),
    ]);

    expect(parsed.success).toBe(true);
    if (!parsed.success) return;
    expect(parsed.data.services?.db?.['x-eve']?.managed?.roles).toEqual([
      { name: 'app', grants: 'readwrite' },
      { name: 'gotrue', grants: { schema: 'auth', owner: true } },
    ]);
  });

  it('refuses public, which every role shares', () => {
    const parsed = parseManifest([owner('public')]);

    expect(parsed.success).toBe(false);
    expect(messages(parsed).join('\n')).toMatch(/public/);
  });

  it.each([
    ['quoted', '"auth"'],
    ['dotted', 'auth.users'],
    ['upper case', 'Auth'],
    ['hyphenated', 'auth-db'],
    ['leading digit', '1auth'],
    ['empty', ''],
    ['too long', 'a'.repeat(64)],
    ['not a string', 7],
  ])('refuses a %s schema name', (_label, schema) => {
    const parsed = parseManifest([owner(schema)]);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.some((issue) => issue.path.includes('grants'))).toBe(true);
  });

  it.each([
    ['pg_ prefixed', 'pg_auth'],
    ['information_schema', 'information_schema'],
  ])('refuses a schema name Postgres reserves (%s)', (_label, schema) => {
    const parsed = parseManifest([owner(schema)]);

    expect(parsed.success).toBe(false);
    expect(messages(parsed).join('\n')).toMatch(/reserved/);
  });

  it('accepts a 63-character schema name', () => {
    expect(parseManifest([owner(`a${'b'.repeat(62)}`)]).success).toBe(true);
  });

  it.each([
    ['owner: false', { name: 'gotrue', grants: { schema: 'auth', owner: false } }],
    ['no owner flag', { name: 'gotrue', grants: { schema: 'auth' } }],
    ['an unknown key', owner('auth', { readonly: true })],
  ])('refuses an object grant with %s', (_label, role) => {
    const parsed = parseManifest([role]);

    expect(parsed.success).toBe(false);
    if (parsed.success) return;
    expect(parsed.error.issues.some((issue) => issue.path.includes('grants'))).toBe(true);
  });

  it('refuses two owner roles for one schema', () => {
    const parsed = parseManifest([
      owner('auth'),
      { name: 'gotrue2', grants: { schema: 'auth', owner: true } },
    ]);

    expect(parsed.success).toBe(false);
    expect(messages(parsed)).toContain('Managed DB schema "auth" has two owner roles (gotrue, gotrue2)');
  });

  it('counts owner roles towards the 8 declared roles', () => {
    const roles = [
      ...Array.from({ length: 8 }, (_, i) => ({ name: `role${i}`, grants: 'readonly' })),
      owner('auth'),
    ];

    expect(messages(parseManifest(roles))).toContain('A managed database declares at most 8 roles (found 9)');
  });

  it('names the accepted forms for an unknown grant', () => {
    expect(messages(parseManifest([{ name: 'app', grants: 'admin' }])).join('\n'))
      .toMatch(/readwrite.*readonly.*owner: true/);
  });
});
