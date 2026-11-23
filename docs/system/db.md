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
- Roles are supported on the local provider; cloud providers reject them with
  `provider_unsupported` until provider support lands.

### Eve's sessions on tenant databases

A tenant owns its database, so it controls that database's settings and what
is in its `public` schema. The reconciler's own connections as the platform
login, to a tenant database (extension installs, declared-role grants) and to
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
