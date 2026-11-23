# Database CLI + Managed DB

> Status: Current
> Last Updated: 2026-11-10
> Purpose: Document environment DB tooling and managed database provisioning.

## Environment DB CLI (Current)

Use `eve db` to inspect and operate on environment-scoped databases:

```bash
eve db schema --env staging [--project <id>]
eve db rls --env staging
eve db extensions list --env staging
eve db sql --env staging --sql "SELECT 1"
eve db sql --env staging --sql "UPDATE ..." --write
eve db sql --env staging --file ./query.sql
eve db migrate --env staging [--path db/migrations]
eve db migrations --env staging
eve db new create_users [--path db/migrations]
```

Migration files use `YYYYMMDDHHmmss_description.sql` under `db/migrations/` by default.

`eve db sql` without `--write` runs in a read-only transaction, as one
statement on the extended protocol. A statement list (`SELECT 1; SELECT 2`)
gets 400: on the simple protocol a list could commit the read-only
transaction and write after it. Send statements one at a time, or use
`--write`, which runs a list as before.

### Which database `--env` targets

The API resolves the environment's database in this order:

1. The environment's DB override (`overrides.db.url`, `connection_url` or
   `database_url`, with an optional `schema`).
2. The manifest service named by the environment's `db_ref`, or else the one
   service with `x-eve.role: database` or `x-eve.role: managed_db`. Managed
   databases use the tenant's own credentials; container databases use
   `x-eve.connection_url`, `connection_url`, `url`, `DATABASE_URL`, or the
   `POSTGRES_*` variables and the service's cluster DNS name.

An environment with none of these has no database: every env-db command
(`schema`, `rls`, `extensions`, `sql`, `migrate`, `migrations`, `reset`,
`wipe`) answers `409` and opens no connection. Declare a database service or
set an override first.

Env-db commands never run against Eve's own platform database. A target is
"on the platform server" when its host and port match the platform's
`DATABASE_URL` (hosts match by name, case-insensitive, by resolved address,
or as loopback). On the platform server:

- the platform database itself is refused with `403`, whatever credentials
  the target carries;
- the platform's own role is refused with `403` on any database
  (`postgres`, `template1`, ...);
- after connecting and before running anything, a login is refused with
  `403` if its session or current role is, or is a member of, a role with
  SUPERUSER, CREATEROLE, BYPASSRLS or REPLICATION, or of `cloudsqlsuperuser`,
  `rds_superuser`, `azure_pg_admin`, `pg_read_all_data`, `pg_write_all_data`
  or the `pg_*_server_*` file roles. The check runs on a connection of its
  own, opened and closed before the command's session, that sends
  `search_path=pg_catalog` at startup (the database's owner and the URL may
  both set a search path) and names every catalog object and operator in full.

On any server, a connection URL may only set the startup parameters
`application_name`, `search_path` and `sslrootcert` (plus client settings
such as `sslmode` and `connect_timeout`). Others, such as `role`, `options`
or `session_authorization`, are refused with `400` before connecting, unless
the platform `DATABASE_URL` sets the same parameter to the same value
(managed tenant URLs inherit the platform URL's parameters). A URL with a
control character (raw or percent-encoded, such as `%00` or `%0A`) in any
part is refused with `400`, and the client is built from the parsed, checked
parts rather than the URL string, so it sends exactly what was checked.

A plain role on another database of that server, such as a managed tenant
database, is allowed. Container databases in the environment's own namespace
are a different server and are not subject to these checks. If the platform
database host cannot be resolved, env-db commands answer `503` rather than
guess.

Earlier versions gave an environment with no database a schema named
`eve_env_<project>_<env>` inside the platform database. Those schemas and
their data are left in place, unused. An operator can list them with a
read-only query against the platform database:

```sql
SELECT schema_name
FROM information_schema.schemata
WHERE schema_name LIKE 'eve\_env\_%'
ORDER BY schema_name;
```

Move any data a tenant still needs into a database of the environment's own,
then drop the schema.

The env DB routes (`/projects/:id/envs/:name/db/...`) address the project by id.
A job token sent in the optional `eve-job-token` header lends its permissions
(for example `envdb:write`) only when it was minted for that same project; any
other header token is a 403 and nothing runs.

## Managed DB (Current)

Managed databases are declared in the manifest as services with `x-eve.role: managed_db`:

```yaml
services:
  db:
    x-eve:
      role: managed_db
      managed:
        class: db.p1
        engine: postgres
        engine_version: "16"
        extensions: [pg_trgm, citext]
        roles:
          - name: app
            grants: readwrite
          - name: reports
            grants: readonly
```

Provisioning occurs when an environment is deployed; managed DB services are not
rendered into Kubernetes manifests.

Managed DB CLI commands:

```bash
eve db status --env staging
eve db extensions list --env staging
eve db rotate-credentials --env staging
eve db scale --env staging --class db.p2
eve db destroy --env staging --force
```

Notes:
- Managed DB availability depends on platform configuration (ask an admin if provisioning is disabled).
- Use `eve db status` to confirm tenant readiness before relying on managed values.
- Managed values can be referenced in env vars via `${managed.<service>.<field>}`.
  Fields: `url` (verbatim owner URL), `host`, `port`, `database`, `username`,
  `password`, `extensions`, and `roles.<name>.url|username|password` for declared
  roles.
- Plain declarable extensions are `postgis`, `pgvector`, `pg_trgm`, `btree_gist`, `hstore`, and `citext`.
- Eve installs a tenant's extensions as its platform login, inside the tenant's
  database and into `public`, which the tenant can write. An extension's install
  script resolves names in that schema first, so an object the tenant planted
  there could run with the platform login's rights. PostgreSQL vouches only for
  the scripts of extensions it marks trusted (`pg_trgm`, `btree_gist`, `hstore`,
  `citext`). `postgis` and `pgvector` are not, and are refused: manifest
  validation rejects them, and the reconciler checks the server's own
  `pg_available_extension_versions.trusted` flag for the version it would
  install and fails the tenant with `provider_unsupported` before any script
  runs. An extension already installed in the database is left as it is.
- `EVE_MANAGED_DB_ALLOW_UNTRUSTED_EXTENSIONS=true` (exactly `true`, on the API,
  worker and orchestrator) lets Eve install untrusted extensions. **This is
  dangerous**: set it only while installing into databases whose `public` no
  tenant can write yet, such as a new database before it is handed over, and
  unset it afterwards.
- Provider-gated preload extensions are rejected unless the platform enables them with `EVE_MANAGED_DB_ENABLED_PRELOAD_EXTENSIONS`. `pg_cron` is the first gated extension; it requires `shared_preload_libraries=pg_cron` on the backing Postgres instance before deploy.
- `pgvector` is declared as `pgvector` in the manifest but appears as `vector` in `pg_extension`.
- `pg_cron` follows the AWS RDS model: Eve installs it in the instance admin database (`postgres`) and grants tenant roles `USAGE` on the `cron` schema. Scheduling jobs for tenant databases remains a platform-admin operation.
- Extension removal is sticky in v1: removing a name from the manifest stops requesting it, but Eve does not run `DROP EXTENSION`.
- `timescaledb` is still not declarable on AWS RDS; Eve treats it as a preload candidate without a supported provider model.
- Missing preload configuration fails the tenant with `preload_missing`; unavailable provider packages fail with `extension_unavailable`.
- Local managed DB URLs default to `sslmode=disable`. Supported cloud providers default to `sslmode=verify-full`.
- The worker owns TLS trust distribution for managed DB clients. For cloud tenants it creates `ConfigMap/eve-db-trust`, mounts `/etc/eve/trust/ca-bundle.pem`, and injects `NODE_EXTRA_CA_CERTS` plus `PGSSLROOTCERT` into Deployments and `x-eve.role: job` pods.
- App code should use the plain connection string from `DATABASE_URL`. Do not set `ssl: { rejectUnauthorized: false }` in Node `pg`.

### Connection limits

Each managed database accepts only its own logins (`CONNECT` is revoked from
`PUBLIC`). Each login (owner and declared roles) gets its class's limit
(25, 100 or 200 for `db.p1`, `db.p2`, `db.p3`) unless it already has one. The
database as a whole gets its class maximum plus a platform reserve of 5
(`MANAGED_DB_PLATFORM_CONNECTION_RESERVE`): 30, 105 or 205. The database
limit counts every login, Eve's own included, and Eve's platform login is not
a superuser on Cloud SQL, so without the reserve a tenant whose logins fill
the database would lock out the reconciler, `eve db`, migrations and the
pre-delete `pg_dump`. A database limit is set only when there is none: one
an operator set, lower or higher, stays as it is (and then the reserve is
theirs to allow for).
The limits are applied at provisioning, when a change to the tenant
finishes, and once to every ready tenant when the orchestrator starts.

The tenant owner owns its database, so it can change the database's limit
itself (`ALTER DATABASE ... CONNECTION LIMIT`), and Eve leaves a limit
already set alone. That limit therefore guards against running out by
accident only; a lower one the owner sets can shut Eve's own connections
out of that database, and no other. A hostile tenant is bounded by the
per-login limits, which the owner cannot change (its logins are
`NOCREATEROLE`), and by the cap of 8 declared roles: at most nine logins,
each at its class's limit.

**Rollout (0.1.328).** The orchestrator's start-up pass applies these limits
as soon as the new release starts, so the pre-check runs **before** the
deploy, read-only, as the instance's admin login, at a busy time of day
(repeat it to see a peak):

```sql
SELECT d.datname, d.datconnlimit,
       (SELECT count(*) FROM pg_stat_activity a WHERE a.datname = d.datname) AS connections
FROM pg_database d WHERE NOT d.datistemplate ORDER BY d.datname;

SELECT r.rolname, r.rolconnlimit,
       (SELECT count(*) FROM pg_stat_activity a WHERE a.usename = r.rolname) AS connections
FROM pg_roles r WHERE r.rolcanlogin ORDER BY r.rolname;
```

Compare each tenant database's connections with its class maximum plus 5,
and each login's with its class limit. Where a tenant is near either, scale
it to a larger class (`eve db scale`) before the deploy. A database that
already has a limit (set by hand, or by its owner) keeps it: the start-up
pass sets one only where there is none, and never raises or lowers one.

### Roles

The tenant owner login is always provisioned. `x-eve.managed.roles` declares
additional least-privilege logins (`grants: readwrite` or `readonly`) named
`<owner user>-<name>` (hash-truncated to 63 characters). Per role the
reconciler runs, as the instance admin:

```sql
CREATE ROLE "<role>" WITH LOGIN NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD '<random>';
GRANT CONNECT ON DATABASE "<db>" TO "<role>";
-- inside the tenant database:
GRANT USAGE ON SCHEMA "public" TO "<role>";
GRANT SELECT[, INSERT, UPDATE, DELETE] ON ALL TABLES IN SCHEMA "public" TO "<role>";
GRANT SELECT[, USAGE] ON ALL SEQUENCES IN SCHEMA "public" TO "<role>";
ALTER DEFAULT PRIVILEGES FOR ROLE "<owner>" IN SCHEMA "public" GRANT ... ON TABLES TO "<role>";
ALTER DEFAULT PRIVILEGES FOR ROLE "<owner>" IN SCHEMA "public" GRANT ... ON SEQUENCES TO "<role>";
```

- Role credentials are stored per role in `managed_db_tenant_roles` the same
  way the owner credential is stored on the tenant, and are exposed only through
  `${managed.<service>.roles.<name>.url|username|password}`.
- Changing `grants` re-grants in place; removing a role revokes its privileges
  and drops the login on the next deploy. Adding a role does not touch existing
  roles or the owner credential.
- `eve db rotate-credentials` rotates every role password with the owner
  password. `eve db destroy` drops the roles with the database.
- `eve db status --env <name>` lists declared and provisioned roles (names and
  logins only, never passwords).
- A managed database declares at most 8 roles; manifest sync refuses more.
  Each login (owner and roles) gets the class's connection limit, and the
  database as a whole the class's maximum plus a platform reserve of 5 (see
  [connection limits](#connection-limits)).
- Roles are supported on the local provider; cloud providers reject them with
  `provider_unsupported` until provider support lands.

### Schema-owner roles

A declared role may own one named schema of the tenant database instead of
holding `public` grants (from 0.1.330). It can create, change and drop
objects in that schema, and gets no grants of its own in `public`. This suits a service
that runs its own migrations in a schema of its own, such as GoTrue in
`auth`, without the owner credential.

```yaml
roles:
  - name: app
    grants: readwrite
  - name: gotrue
    grants: { schema: auth, owner: true }
```

```yaml
environment:
  GOTRUE_DB_DATABASE_URL: postgres://${managed.db.roles.gotrue.username}:${managed.db.roles.gotrue.password}@${managed.db.host}:${managed.db.port}/${managed.db.database}?search_path=auth
```

- The schema is a plain lower-case identifier (`[a-z_][a-z0-9_]*`, at most 63
  characters, no quotes or dots). Manifest sync refuses `public`, `pg_*`,
  `information_schema` and two owner roles for one schema. An owner role
  counts towards the 8 roles and gets the class's connection limit.
- The login is created like any declared role and granted `CONNECT`. Eve's
  platform login is made a member of it, as of the owner role, so it can give
  the role its schema and take it back. When the tenant is provisioned again
  (retried after a failure, or revived after a destroy), the login is set up
  again with a new password, as the owner credential is.
- On every provisioning or modifying run (a deploy that changes the tenant),
  inside the tenant database:
  - **no such schema:** `CREATE SCHEMA <schema> AUTHORIZATION <role>`;
  - **owned by the tenant owner:** Eve hands it over in one transaction: the
    schema, then every table, view, materialised view, sequence, foreign
    table, type, domain, function, procedure and aggregate in it that the
    owner owns (indexes and column sequences follow their table, array types
    their element, extension members their extension), and it revokes what
    `PUBLIC` and the tenant's other logins held on the schema. The
    orchestrator logs the counts. Each change takes an exclusive lock on its
    object, so the transaction waits at most 5 seconds for a lock and fails
    otherwise: hand over a busy schema in a quiet hour;
  - **owned by the role:** nothing;
  - **owned by any other role, holding an object another role owns, or
    holding an object a hand-over does not move:** the tenant goes `failed`
    with `schema_owner_conflict` and a reason naming the objects, and nothing
    changes. The kinds a hand-over does not move are operators, operator
    classes and families, collations, conversions, statistics objects,
    text-search configurations and dictionaries, and ordered-set aggregates
    (members of an extension excepted): move them to another schema or drop
    them, then deploy again. The check runs before any role is created or
    dropped.
- The role gets no grants of its own in `public`. Like every role it keeps
  what `PUBLIC` holds there: on Postgres 15 defaults, `USAGE` on the schema
  and `EXECUTE` on its functions (14 and older also grant `CREATE`), so it
  can call a function in `public` but not read a table there unless granted.
- The tenant's other logins get nothing in its schema, except that the tenant
  owner can read it: `USAGE` on the schema and `SELECT` on its tables and
  sequences, including those the role creates later (default privileges).
  Snapshots run `pg_dump` as the tenant owner, so this keeps the schema in
  every scheduled, pre-delete and pre-reset snapshot. The owner cannot change
  anything there. If the role turns on row-level security for a table,
  snapshots fail: the owner is not that table's owner, so `pg_dump` refuses.
- Removing the role from the manifest first stops it signing in (`NOLOGIN`)
  and ends its sessions, waiting for each, so nothing it commits meanwhile is
  lost or keeps the login. Then, in one transaction: its `SECURITY DEFINER`
  functions and procedures, in the schema or elsewhere in the database,
  become `SECURITY INVOKER`; every privilege anyone but the tenant owner
  holds on the schema and on the role's tables, views, sequences, routines
  and types is revoked, with `CASCADE` (so what they passed on goes too),
  `PUBLIC`'s included (functions grant it `EXECUTE`, types `USAGE`); its
  schema and everything else it owns in the database go back to the tenant
  owner and its privileges there are revoked (`ALTER SCHEMA ... OWNER TO`,
  `REASSIGN OWNED`, `DROP OWNED`, which also removes the default privileges
  that let the owner read new objects). The login is then dropped. The data
  stays. If that transaction fails (a lock held past 5 seconds, say),
  nothing has moved, the tenant goes `failed` with `schema_hand_back_failed`
  and the reason, and the role is kept, still unable to sign in, since it is
  being removed; the next deploy hands the schema back and drops it.
  Changing a role between `public` grants and an owned schema, or to
  another schema, drops it this way and creates it again with a new
  password (its login stays off until that hand-back succeeds).
- So nothing the role made runs or reads with the tenant owner's rights for
  another login after the hand-back: its functions run as their caller, and
  only the owner (and Eve's platform login, as a member of it) can use the
  schema or anything in it. What remains is the owner's to review: a view
  reads with its owner's rights, now the tenant owner's, and the owner's own
  calls run the role's code as the owner. Check the role's views and
  functions before granting them to another login or switching a function
  back to `SECURITY DEFINER`.
- `eve db rotate-credentials` rotates its password with the others;
  `eve db destroy` drops it with the database; `eve db reset` resets `public`
  only, so an owned schema is kept.
- Owner roles are stored in `managed_db_tenant_schema_owners` (migration
  00124), apart from `managed_db_tenant_roles`.

**Rollback below 0.1.330.** Remove the owner role from the manifest and
deploy under 0.1.330 first: the schema goes back to the tenant owner and the
login is dropped. Then roll back, and point the service at a credential the
older release provides. If the release is rolled back with an owner role
still in place, the older release neither drops nor changes the role: it
reads only `managed_db_tenant_roles`, so the login keeps its schema and
password and running services keep working. It cannot deploy or sync the
manifest (it refuses the object grant) until 0.1.330 is back, and an
`eve db destroy` there leaves the owner login behind for the operator to
drop (`DROP ROLE`). While rolled back, do not declare the same role name as
a `readwrite` or `readonly` role: the older release would make the same
login (`<owner user>-<name>`) a data role too, with a new password (so the
service using the owner role can no longer sign in) and grants in `public`,
while it still owns the schema (a registered residual).

### Eve's sessions on tenant databases

A tenant owns its database, so it controls that database's settings and what
is in its `public` schema. The reconciler's own connections as the platform
login, to a tenant database (extension installs, declared-role grants,
schema-owner hand-overs) and to
the instance admin database, therefore send `search_path=pg_catalog`,
`role=none` and `default_transaction_read_only=off` in the startup message: a
startup value overrides any per-database or per-role default (so a tenant's
`ALTER DATABASE ... SET role` or `SET default_transaction_read_only = on` does
not apply to them) and applies before the first query, and any of the three in
`DATABASE_URL`'s query string is dropped for these connections. They also skip the client's startup type query
(postgres.js `fetch_types: false`), so they handle built-in scalar types only
(arrays come back as text). Statements on them name catalog objects in full
(`pg_catalog.pg_roles`, `pg_catalog.pg_terminate_backend`) and name the schema
of anything they create or grant in a tenant database
(`CREATE EXTENSION ... SCHEMA "public"`, `GRANT ... IN SCHEMA "public"`).
Connections made with a tenant's own credentials (apps, `eve db`, snapshots and
restores) keep the database's own settings.

## Admin APIs (Managed DB Instances)

Managed DB instances are registered via admin endpoints:

```
GET  /admin/managed-db/instances
POST /admin/managed-db/instances
GET  /admin/managed-db/instances/:id
```

Project/env tenant endpoints:

```
GET    /projects/:project_id/envs/:env_name/db/managed
POST   /projects/:project_id/envs/:env_name/db/managed/rotate
POST   /projects/:project_id/envs/:env_name/db/managed/scale
DELETE /projects/:project_id/envs/:env_name/db/managed
```
