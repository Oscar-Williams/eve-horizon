import postgres from 'postgres';

export function createDb(connectionString: string) {
  return postgres(connectionString, {
    max: 10,
    idle_timeout: 20,
    connect_timeout: 10,
  });
}

export type Db = ReturnType<typeof createDb>;

/**
 * Startup parameters Eve's sessions on other owners' databases send. A value
 * sent at startup takes precedence over the owner's per-database and per-role
 * defaults (ALTER DATABASE / ALTER ROLE ... SET), and applies before the
 * first query.
 */
const PINNED_SESSION_PARAMETERS: Readonly<Record<string, string>> = {
  // The only schema names resolve in.
  search_path: 'pg_catalog',
  // Act as the login itself, not a role the owner names (SET role = ...).
  role: 'none',
  // Eve's statements may write, whatever read-only default the owner sets.
  default_transaction_read_only: 'off',
};

const PINNED_SESSION_PARAMETER_NAMES = new Set(Object.keys(PINNED_SESSION_PARAMETERS));

/** Whether a startup parameter is pinned (Postgres matches names ignoring case). */
function isPinnedSessionParameter(name: string): boolean {
  return PINNED_SESSION_PARAMETER_NAMES.has(name.toLowerCase());
}

/**
 * A client for Eve's own login on a database someone else owns, such as a
 * managed tenant database. The owner may set that database's search_path
 * and create objects named like built-ins, so the session's search_path is
 * sent as pg_catalog in the startup message (ahead of any per-database
 * setting, and of the first query). The owner may also set the database's
 * role and default_transaction_read_only, so those are sent as none and
 * off. Any of the three in the connection string's query is dropped (the
 * pinned values replace it). The client's startup type query is not sent,
 * so arrays come back as text: use built-in scalar types only. Statements
 * should still name catalog objects, and the schemas they create in, in full.
 */
export function createPinnedSearchPathDb(connectionString: string): Db {
  const url = new URL(connectionString);
  for (const name of [...url.searchParams.keys()]) {
    if (isPinnedSessionParameter(name)) url.searchParams.delete(name);
  }
  return postgres(url.toString(), {
    max: 10,
    idle_timeout: 20,
    connect_timeout: 10,
    fetch_types: false,
    connection: { ...PINNED_SESSION_PARAMETERS },
  });
}

export type ConnectionTarget = {
  /** Servers in the order the client tries them. */
  endpoints: Array<{ host: string; port: number }>;
  /** Database named in the startup message. */
  database: string;
  /** Role named in the startup message. */
  user: string;
  /**
   * Every other server parameter the client sends at startup (from the URL's
   * query string, e.g. application_name, options or role), by name.
   */
  startupParameters: Record<string, string>;
  /**
   * Everything the client would send or connect with, as parsed. Pass the
   * whole target to createDbFromTarget so what was checked is what is used.
   */
  clientOptions: {
    host: string[];
    port: number[];
    path: string | null;
    database: string;
    user: string;
    password: string;
    ssl: unknown;
    targetSessionAttrs: string | null;
    connection: Record<string, string>;
  };
};

const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/;

/**
 * The parts of a target that hold a control character (NUL, newline, ...),
 * by name. Values are not returned. Such a character in a startup value
 * would let one field carry extra startup pairs.
 */
export function connectionTargetControlCharacters(target: ConnectionTarget): string[] {
  const options = target.clientOptions;
  const found: string[] = [];
  const check = (label: string, value: unknown) => {
    if (typeof value === 'string' && CONTROL_CHARACTERS.test(value)) found.push(label);
  };
  options.host.forEach((host) => check('host', host));
  check('path', options.path);
  check('database', options.database);
  check('user', options.user);
  check('password', options.password);
  check('ssl', options.ssl);
  check('target_session_attrs', options.targetSessionAttrs);
  for (const [name, value] of Object.entries(options.connection)) {
    check('parameter name', name);
    check(`parameter ${CONTROL_CHARACTERS.test(name) ? '(name)' : name}`, value);
  }
  return [...new Set(found)];
}

/**
 * Where a connection string points, read by the same parser `createDb`
 * connects with (so defaults, multi-host lists and startup parameters such
 * as `?database=` count). Opens no connection.
 */
export function describeConnectionTarget(connectionString: string): ConnectionTarget {
  const { options } = postgres(connectionString);
  const startupDatabase = options.connection?.database;
  const startupUser = options.connection?.user;
  const database = typeof startupDatabase === 'string' && startupDatabase.length > 0
    ? startupDatabase
    : options.database;
  const user = typeof startupUser === 'string' && startupUser.length > 0 ? startupUser : options.user;
  const connection = Object.fromEntries(
    Object.entries(options.connection ?? {})
      .filter(([name]) => name !== 'database' && name !== 'user')
      .map(([name, value]) => [name, String(value)]),
  );
  const raw = options as unknown as {
    path?: string | false;
    pass?: unknown;
    ssl?: unknown;
    target_session_attrs?: unknown;
  };
  return {
    endpoints: options.host.map((host, index) => ({
      host,
      port: options.port[index] ?? options.port[0],
    })),
    database,
    user,
    startupParameters: connection,
    clientOptions: {
      host: [...options.host],
      port: [...options.port],
      path: typeof raw.path === 'string' ? raw.path : null,
      database,
      user,
      password: typeof raw.pass === 'string' ? raw.pass : '',
      ssl: raw.ssl ?? false,
      targetSessionAttrs: typeof raw.target_session_attrs === 'string' ? raw.target_session_attrs : null,
      connection,
    },
  };
}

/**
 * A client built only from a target's parsed options (never from the raw
 * URL), so the user, database and startup parameters it sends are exactly
 * those that were described and checked. Callers should refuse targets with
 * control characters first (connectionTargetControlCharacters).
 *
 * `pinned` pins the session as createPinnedSearchPathDb does: the pinned
 * startup parameters replace any the target sets, and the startup type query
 * is not sent. Use it for Eve's own checks on a database whose owner Eve does
 * not trust, before the target's own session runs anything.
 */
export function createDbFromTarget(target: ConnectionTarget, { pinned = false }: { pinned?: boolean } = {}) {
  const options = target.clientOptions;
  const connection = pinned
    ? {
      ...Object.fromEntries(Object.entries(options.connection).filter(([name]) => !isPinnedSessionParameter(name))),
      ...PINNED_SESSION_PARAMETERS,
    }
    : { ...options.connection };
  return postgres({
    host: options.host,
    port: options.port,
    ...(options.path ? { path: options.path } : {}),
    database: options.database,
    username: options.user,
    password: options.password,
    ssl: options.ssl,
    ...(options.targetSessionAttrs ? { target_session_attrs: options.targetSessionAttrs } : {}),
    connection,
    ...(pinned ? { fetch_types: false } : {}),
    max: 10,
    idle_timeout: 20,
    connect_timeout: 10,
  } as unknown as postgres.Options<Record<string, never>>) as unknown as Db;
}
