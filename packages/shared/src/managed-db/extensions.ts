export const PLAIN_EXTENSION_NAMES = [
  'postgis',
  'pgvector',
  'pg_trgm',
  'btree_gist',
  'hstore',
  'citext',
] as const;

export const PROVIDER_GATED_EXTENSION_NAMES = [
  'pg_cron',
] as const;

export const SUPPORTED_EXTENSION_NAMES = [
  ...PLAIN_EXTENSION_NAMES,
  ...PROVIDER_GATED_EXTENSION_NAMES,
] as const;

export type SupportedExtension = typeof SUPPORTED_EXTENSION_NAMES[number];
export type PlainSupportedExtension = typeof PLAIN_EXTENSION_NAMES[number];
export type ProviderGatedExtension = typeof PROVIDER_GATED_EXTENSION_NAMES[number];

export const MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV =
  'EVE_MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS';

/**
 * Set to exactly `true` to let Eve install tenant extensions PostgreSQL does
 * not mark trusted. Dangerous: see untrustedManagedDbExtensionError.
 */
export const MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS_ENV =
  'EVE_MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS';

export type SupportedExtensionDefinition =
  | {
    mode: 'plain';
    extname: string;
    installScope: 'tenant_db';
    /**
     * Whether PostgreSQL ships the extension marked trusted (`trusted = true`
     * in its control file). Manifest validation goes by this; at install time
     * the server's own flag decides.
     */
    trusted: boolean;
  }
  | {
    mode: 'preload';
    extname: string;
    preloadName: string;
    installScope: 'instance_admin_db';
    schema: string;
    providerHint: string;
  };

export const SUPPORTED_EXTENSIONS: Record<SupportedExtension, SupportedExtensionDefinition> = {
  postgis: { mode: 'plain', extname: 'postgis', installScope: 'tenant_db', trusted: false },
  pgvector: { mode: 'plain', extname: 'vector', installScope: 'tenant_db', trusted: false },
  pg_trgm: { mode: 'plain', extname: 'pg_trgm', installScope: 'tenant_db', trusted: true },
  btree_gist: { mode: 'plain', extname: 'btree_gist', installScope: 'tenant_db', trusted: true },
  hstore: { mode: 'plain', extname: 'hstore', installScope: 'tenant_db', trusted: true },
  citext: { mode: 'plain', extname: 'citext', installScope: 'tenant_db', trusted: true },
  pg_cron: {
    mode: 'preload',
    extname: 'pg_cron',
    preloadName: 'pg_cron',
    installScope: 'instance_admin_db',
    schema: 'cron',
    providerHint: 'Configure shared_preload_libraries=pg_cron on the backing instance before enabling pg_cron.',
  },
};

export const PRELOAD_EXTENSION_CANDIDATES = {
  pg_cron: {
    extname: 'pg_cron',
    preloadName: 'pg_cron',
    installScope: 'instance_admin_db',
  },
  timescaledb: {
    extname: 'timescaledb',
    preloadName: 'timescaledb',
    installScope: 'tenant_db',
    providerNote: 'not supported by AWS RDS PostgreSQL as of 2026-05-18',
  },
} as const;

const SUPPORTED_EXTENSION_SET = new Set<string>(SUPPORTED_EXTENSION_NAMES);
const PLAIN_EXTENSION_SET = new Set<string>(PLAIN_EXTENSION_NAMES);
const PROVIDER_GATED_EXTENSION_SET = new Set<string>(PROVIDER_GATED_EXTENSION_NAMES);

export function isSupportedExtensionName(name: string): name is SupportedExtension {
  return SUPPORTED_EXTENSION_SET.has(name);
}

export function isPlainExtensionName(name: string): name is PlainSupportedExtension {
  return PLAIN_EXTENSION_SET.has(name);
}

export function isProviderGatedExtensionName(name: string): name is ProviderGatedExtension {
  return PROVIDER_GATED_EXTENSION_SET.has(name);
}

export function isKnownManagedDbExtensionName(name: string): boolean {
  return isSupportedExtensionName(name) || name in PRELOAD_EXTENSION_CANDIDATES;
}

export function parseEnabledPreloadExtensions(value: string | undefined): ProviderGatedExtension[] {
  if (!value) {
    return [];
  }

  const requested = new Set(
    value
      .split(',')
      .map((entry) => entry.trim())
      .filter(Boolean),
  );

  if (requested.has('*')) {
    return [...PROVIDER_GATED_EXTENSION_NAMES];
  }

  return PROVIDER_GATED_EXTENSION_NAMES.filter((extension) => requested.has(extension));
}

export function getEnabledPreloadExtensions(): ProviderGatedExtension[] {
  return parseEnabledPreloadExtensions(process.env[MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV]);
}

export function isManagedDbExtensionEnabled(
  name: SupportedExtension,
  opts?: { enabledPreloadExtensions?: readonly string[] },
): boolean {
  if (isPlainExtensionName(name)) {
    return true;
  }

  const enabled = new Set(opts?.enabledPreloadExtensions ?? getEnabledPreloadExtensions());
  return enabled.has(name);
}

export function untrustedManagedDbExtensionsAllowed(): boolean {
  return process.env[MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS_ENV] === 'true';
}

/**
 * Why Eve refuses a tenant extension PostgreSQL does not mark trusted. Eve
 * installs it as its platform login inside the tenant's database, into
 * "public", which the tenant can write; the install script resolves names
 * there first, so an object the tenant planted could run with Eve's rights.
 */
export function untrustedManagedDbExtensionError(name: string): string {
  return (
    `Managed DB extension "${name}" is not marked trusted by PostgreSQL, so Eve does not install it: ` +
    `its install script would run as Eve's platform login in the tenant database's "public" schema, ` +
    `which the tenant can write. A platform admin may set ${MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS_ENV}=true ` +
    `on the API, worker and orchestrator to allow it. That is dangerous: install it only into databases ` +
    `whose "public" no tenant can write yet, such as a new database before it is handed over.`
  );
}

export function getManagedDbExtensionValidationError(
  name: string,
  opts?: { enabledPreloadExtensions?: readonly string[] },
): string | null {
  if (!isSupportedExtensionName(name)) {
    if (isKnownManagedDbExtensionName(name)) {
      return `Managed DB extension "${name}" is a preload candidate but is not supported by the current provider model`;
    }
    return `Unsupported managed DB extension "${name}". Supported extensions: ${SUPPORTED_EXTENSION_NAMES.join(', ')}`;
  }

  if (!isManagedDbExtensionEnabled(name, opts)) {
    return `Provider-gated managed DB extension "${name}" is disabled. Configure provider preload support and set ${MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS_ENV}=${name}.`;
  }

  const definition = SUPPORTED_EXTENSIONS[name];
  if (definition.mode === 'plain' && !definition.trusted && !untrustedManagedDbExtensionsAllowed()) {
    return untrustedManagedDbExtensionError(name);
  }

  return null;
}

export function normalizeManagedDbExtensions(
  extensions: readonly string[] | null | undefined,
  opts?: {
    enabledPreloadExtensions?: readonly string[];
    includeDisabledProviderGated?: boolean;
  },
): SupportedExtension[] {
  if (!extensions || extensions.length === 0) {
    return [];
  }

  const requested = new Set<SupportedExtension>();
  for (const extension of extensions) {
    if (!isSupportedExtensionName(extension)) {
      throw new Error(
        getManagedDbExtensionValidationError(extension, opts) ??
        `Unsupported managed DB extension: ${extension}`,
      );
    }
    if (!opts?.includeDisabledProviderGated && !isManagedDbExtensionEnabled(extension, opts)) {
      throw new Error(
        getManagedDbExtensionValidationError(extension, opts) ??
        `Disabled managed DB extension: ${extension}`,
      );
    }
    requested.add(extension);
  }

  return SUPPORTED_EXTENSION_NAMES.filter((extension) => requested.has(extension));
}

export function getSupportedExtensionDefinition(
  extension: SupportedExtension,
): SupportedExtensionDefinition {
  return SUPPORTED_EXTENSIONS[extension];
}

export function sharedPreloadLibrariesContains(setting: string | null | undefined, preloadName: string): boolean {
  return (setting ?? '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean)
    .includes(preloadName);
}

export function quotePostgresIdentifier(identifier: string): string {
  return `"${identifier.replace(/"/g, '""')}"`;
}
