# Security profiles

A security profile decides what each hardening rule does. Eve uses profiles
so that stricter defaults can arrive without breaking existing apps: you see
what would change before anything does.

| Profile | What a rule does |
|---|---|
| `legacy` | Nothing: the old behaviour. |
| `audit` | The old behaviour, plus a finding recording what `strict` would refuse. |
| `strict` | The rule is enforced: the request gets 403, and a finding is recorded. |

## Where a profile is set

- **The instance:** the system setting `security.profile`. A fresh database,
  and an existing one after the upgrade that brought profiles, starts on
  `audit`.
- **An org:** overrides the instance.
- **A project:** overrides its org.
- **New projects:** the system setting `security.new_project_profile`, when
  set, is written onto each project as it is created.

Only system admins set profiles, at every level:

```bash
eve system security profile audit                          # instance
eve system security profile strict --project proj_xxx      # one project
eve system security profile clear --project proj_xxx       # inherit again
eve system security profile strict --new-projects          # default for new projects
```

Clearing an org or project profile makes it inherit again. Clearing the
instance profile leaves no instance profile, which means `legacy`; set
`audit` instead to keep recording. Each change is written to the audit log
(entity type `security_profile`) with the system admin who made it and the
old and new profile; the change and its record commit together.

## Rule sets and stamps

Each rule belongs to the rule set of the release step that brought it: the
P1 rules (0.1.326) are rule set 1, the P2 rules (0.1.327) rule set 2. A
`strict` profile is stamped with the rule set current when it was set
(`security_profile_ruleset` on orgs and projects, the system setting
`security.profile_ruleset` for the instance). A rule newer than the stamp
runs under `audit` there: it is recorded, not enforced. So a release never
starts enforcing new rules on a profile already `strict`; nothing changes
until someone moves that profile on.

- Profiles that were `strict` before stamps existed are stamped 1. A `strict`
  with no stamp reads as 1.
- Setting `strict` again stamps the current rule set, which takes the new
  rules: `eve system security profile strict --project proj_xxx`.
- A project created under `security.new_project_profile = strict` is stamped
  with the current rule set.
- `legacy` and `audit` carry no stamp.
- The API, and the worker and orchestrator (`decideSecurityRule`), resolve
  stamps the same way. New behaviour always gets a new rule id, never a wider
  meaning for an old one, so a stamp keeps what it covered.

`eve doctor security` shows what each `strict` covers, for example
`strict (P1 rules); P2 rules on audit`.

Each rule is governed by the profile of the side it protects:
- **Identity rules** follow the instance, because the app calling them is
  the party they guard against.
- **A project's own resources** follow the project.
- **Org-wide data** follows the org.

## Findings and the report

A finding records the rule, the org and project, and who acted: a user, a
job, a service, a service principal or an app link. It never records a value,
token or request body. Findings are kept one row per rule, scope, actor and
day, with a count.

```bash
eve doctor security                       # every org and project
eve doctor security --project proj_xxx    # one project
eve doctor security --days 7 --json
```

A project whose report shows no findings for a few days of normal use can
move to `strict`. Switching back is instant: set the profile to `audit`
again.

## Rules

Each hardening rule lists its id, its governing profile and what `strict`
changes. Rules are added release by release, one rule set per release step.

### Rule set 1 (0.1.326)

| Rule | Governs | Under `strict` |
|---|---|---|
| `jobs.run_step_change` | Project | The jobs of a workflow or pipeline run (root and compiled steps) change only through the run: changes to what they run, phase moves (including done and cancelled), `review_required`, claim, release, submit, approve and reject come only from the run's actor with their own user token, a job token of one of the run's compiled steps, or a project admin (`jobs:admin`). Adding or removing a run root's dependencies counts as a change to it. A compiled step's token may not lower `review_required` on any job. Cancelling a compiled step also cancels the steps after it in its own run, and a compiled step's failure cancels only the steps of its own run. |
| `jobs.dependency_change` | Project | The dependencies of a job outside any run change only for its actor (or their agents), its own job token, or a project admin (`jobs:admin`). |
| `jobs.approve_token` | Project | Job approve and reject, and a `PATCH` that settles a review (moving a job out of `review`, changing `review_required` while in review, or lowering `review_required` in any phase), need a person's own token: job, service, service-principal and app-link tokens get 403. |
| `pipelines.approve_token` | Project | Pipeline-run approve needs a person's own token: job, service, service-principal and app-link tokens get 403. |
| `harness.no_preference` | Project | An agent job with no harness named, no `x-eve.defaults.harness_preference` and no instance `harness_preference` fails at dispatch ("no harness configured") instead of using the built-in list. |
| `harness.missing_credential` | Project | A harness credential counts only from project, org, system or job-actor secrets, never from the orchestrator's or worker's own environment or credential files: harness preferences skip a harness without one, and an agent job whose harness is named (on the job or by its profile) fails at dispatch without one. Under `audit`, a job that runs on such a host credential is recorded. |
| `harness.missing_profile` | Project | A harness profile that is not declared, or that cannot be read, fails the manifest sync (workflow steps), the agents sync (agents and workflow steps) and dispatch (a job naming the profile). |
| `harness.missing_agent` | Project | A workflow step naming an agent that does not exist fails the agents sync and the workflow invoke, before any job is created. |
| `harness.reserved_env` | Project | Env overrides may not set names that load code or libraries (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `PYTHONSTARTUP`), nor `SSL_CERT_DIR`, `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` unless a single `${secret.KEY}`: job create, chat hints, workflow invoke and manifest sync refuse them (403), and the run strips them from jobs that still carry them. Names reserved on every profile are recorded under this rule when a stored job or definition carries them. |
| `harness.user_secret_routing` | Project | User-scope secrets named like model routing settings (`*_BASE_URL`, proxies, TLS trust and the other routing names) or names that load code (`NODE_OPTIONS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_*`, `BASH_ENV`, `ENV`, `PYTHONPATH`, `PYTHONSTARTUP`) are left out when the project's secrets are resolved for a job; a project or org secret of the same name applies instead. |
| `ports.implicit_public` | Project | A service that lists ports and has no `x-eve.ingress` block gets no public ingress, default host, alias or domain; it needs `x-eve.ingress.public: true`, and its next deploy removes an Ingress an earlier deploy made for it. Preview URLs and `eve env diagnose` follow the same rule. |
| `access.implicit_project` | Project | An org `member` gets nothing on a project from the org role alone: rights there come from a project membership or bindings. Applies to permission checks, `eve access can`, project listing and org-wide job, event and agent queries. A binding counts only when its role belongs to the project's org and grants what the listing needs (`projects:read` for the project list and agents, `jobs:read` for jobs and job stats, `events:read` for events); an org-wide binding counts. Org owners and admins are unchanged. `eve access can` answers under this rule without recording a finding. |
| `access.unresolved_project` | Project (the project's own profile for a deleted project named by id; the instance when the project cannot be found) | A permission check for a project that cannot be looked up refuses instead of granting the member set. A failed lookup of a project or its profile is an error under every profile, never the member set. |
| `access.org_route_project` | Project | An org route that reaches a project's resource needs the right a project route would need there: org thread routes on a project's thread (`threads:read`, `threads:write`), `job_attachments:` resolution (`jobs:read` on the job's project), thread distillation (`threads:read`), and the attachments (`jobs:read`) and events (`events:read`) of org search. A refusal gets 403, or the result is left out of the search. |
| `chat.sender_rights` | Project | Chat starts agent work only for a sender who maps to an Eve user holding `jobs:write` on the project; unmapped senders are refused. |
| `access.org_data_unscoped` | Org that owns the data | A job token with no `scope` gets no org file, doc or cloud-fs access, and a job with no `scope` gets no org-fs mount from its user's bindings. |
| `access.org_data_no_user` | Org that owns the data | A job token for work no user started (event, schedule or system runs) gets no org file, doc or cloud-fs access. A workflow or pipeline step that such a run would create with org files, docs or cloud-fs in its declared `scope` is refused (400); its env-db entries stand. The orchestrator mounts no org files for such a job. |
| `access.org_data_scope_wide` | Org that owns the data | Each org file, doc or cloud-fs entry of a job scope a user declares (workflow and pipeline steps, retries), `*` included, must sit inside that user's role bindings (direct or through a group, org-wide or on the project); built-in roles do not count, except an org owner's or admin's. Otherwise 400. Pipeline steps gained the check in this release, so under `legacy` they are still not judged. |
| `access.org_data_scope_unjudged` | Org that owns the data | A job gets org files, docs or cloud-fs from its declared scope only when the API judged that scope for the user who started the work (`jobs.token_scope_judged_at`, cleared when someone else becomes the job's actor unless it is judged again for them). Otherwise the orchestrator gives the job no org-fs mount and only the env-db part of its scope, script and `run` action jobs mint their token with only the env-db part, and the API refuses the token org data. |
| `access.org_data_role_wildcard` | Org that owns the data | A built-in project role (owner, admin, member), and the org `member` role, no longer carry a wildcard scope over the org's files, docs and cloud-fs mounts; their env-db scope stands. Members reach org data only through bindings. Org owners and admins keep theirs. |
| `access.org_data_route_scope` | Org that owns the data | A check on org files, docs or cloud-fs that names no single resource is judged on what the route reaches, for people (their bindings; the org `member` role's wildcard does not count) and for job tokens (their declared `scope`). Org doc lists, queries, searches and stale listings, memory and org search, org-fs object listings, events (list and stream), links, conflicts, shares and public paths return only what the caller reaches; a share token is shown only for a path the caller reaches. Agent KV (`/agents/<slug>/kv/<namespace>/<key>`), thread distillation (the doc it writes), org-fs object listings by prefix, new shares and new public paths are judged on the path they act on. Org-fs status, device enrolment, links and conflicts with no path, share revocation and public path removal need the org's whole filesystem. Org search for a job token also keeps only its own project's attachments and events, and no org threads. Cloud-fs mount listing and default-mount reads need a `cloud_fs` entry in a token's scope, and show a person only the mounts their grants reach. |
| `sso.session_origin` | Instance | The SSO's `/session` and `/logout` serve only the Eve dashboard (no `project_id`), the SSO itself for `/logout`, and an https host of the named project with `x-eve.auth` (default environment hosts, ingress aliases, verified custom domains, manifest `allowed_redirect_origins`). Any other origin, or none, gets 403. |
| `sso.app_access` | Instance | `/session` gives an app a token only for a person its app-access policy admits; anyone else gets 403. |
| `sso.audience_token` | Instance | An app gets a one-hour audience token (`aud` `eve-app:<project>[:<env>]`, no `orgs` claim) instead of the platform token. Under `audit` each app session that would get one is recorded. |

### Rule set 2 (0.1.327)

A profile stamped 1 runs these under `audit` until `strict` is set again.

| Rule | Governs | Under `strict` |
|---|---|---|
| `secrets.value_read` | Project | Secret values are write-only through the API: `POST /projects/:id/secrets/export` gets 403. `ensure` returns a value it generates once, in its own response, and `eve github setup` returns the webhook secret only when it creates it (`secret` is `null` otherwise; `--regenerate` makes a new one). Under `audit`, each export is recorded. |
| `secrets.legacy_ciphertext` | Instance | A `v1` secret, or an integration token or OAuth client secret stored plain, is refused when read, and new writes use `v2`. Under `audit`, each such read is recorded. `eve system security profile strict` on the instance gets 409, naming the count, while any `v1` or plain rows remain: run `eve system secrets reencrypt` first (`--dry-run` shows the count), or override with `--force` (recorded in the audit log). Org and project flips are not checked. See [secrets](secrets.md#storage-at-rest). |

Always on in 0.1.327, whatever the profile: reads of both ciphertext formats
and of sealed or plain OAuth columns; masks that show no character of a
value; and OAuth state stored with its expiry and bound to the user (or
signed-link install cookie) that started the install.
