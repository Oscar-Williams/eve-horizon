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
old and new profile.

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
changes. Rules are added release by release.

| Rule | Governs | Under `strict` |
|---|---|---|
| `jobs.run_step_change` | Project | The jobs of a workflow or pipeline run (root and compiled steps) change only through the run: changes to what they run, phase moves (including done and cancelled), `review_required`, claim, release, submit, approve and reject come only from the run's actor with their own user token, a job token of one of the run's compiled steps, or a project admin (`jobs:admin`). Cancelling a compiled step also cancels the steps after it. |
| `jobs.approve_token` | Project | Job approve and reject, a `PATCH` from `review` to `done`, and a `review_required` change while in review need a person's own token: job, service, service-principal and app-link tokens get 403. |
| `pipelines.approve_token` | Project | Pipeline-run approve needs a person's own token: job, service, service-principal and app-link tokens get 403. |
| `harness.no_preference` | Project | An agent job with no harness named, no `x-eve.defaults.harness_preference` and no instance `harness_preference` fails at dispatch ("no harness configured") instead of using the built-in list. |
| `harness.missing_credential` | Project | An agent job whose harness is named (on the job or by its profile) fails at dispatch when no project, org, system or job-actor secret gives that harness a credential. |
| `harness.missing_profile` | Project | A harness profile that is not declared, or that cannot be read, fails the manifest sync (workflow steps), the agents sync (agents and workflow steps) and dispatch (a job naming the profile). |
| `harness.missing_agent` | Project | A workflow step naming an agent that does not exist fails the agents sync and the workflow invoke, before any job is created. |
| `harness.user_secret_routing` | Project | User-scope secrets named like model routing settings (`*_BASE_URL`, proxies, TLS trust and the other routing names), `NODE_OPTIONS`, `LD_PRELOAD` or `BASH_ENV` are left out when the project's secrets are resolved for a job; a project or org secret of the same name applies instead. |
| `ports.implicit_public` | Project | A service that lists ports and has no `x-eve.ingress` block gets no public ingress, default host, alias or domain; it needs `x-eve.ingress.public: true`. Preview URLs and `eve env diagnose` follow the same rule. |
| `access.implicit_project` | Project | An org `member` gets nothing on a project from the org role alone: rights there come from a project membership or bindings. Applies to permission checks, `eve access can`, project listing and org-wide job, event and agent queries. A binding counts only when its role belongs to the project's org and grants what the listing needs (`projects:read` for the project list and agents, `jobs:read` for jobs and job stats, `events:read` for events); an org-wide binding counts. Org owners and admins are unchanged. `eve access can` answers under this rule without recording a finding. |
| `access.unresolved_project` | Project (the project's own profile for a deleted project named by id; the instance when the project cannot be found) | A permission check for a project that cannot be looked up refuses instead of granting the member set. A failed lookup of a project or its profile is an error under every profile, never the member set. |
| `access.org_route_project` | Project | An org route that reaches a project's resource needs the right a project route would need there: org thread routes on a project's thread (`threads:read`, `threads:write`), `job_attachments:` resolution (`jobs:read` on the job's project), thread distillation (`threads:read`), and the attachments (`jobs:read`) and events (`events:read`) of org search. A refusal gets 403, or the result is left out of the search. |
| `chat.sender_rights` | Project | Chat starts agent work only for a sender who maps to an Eve user holding `jobs:write` on the project; unmapped senders are refused. |
| `access.org_data_unscoped` | Org that owns the data | A job token with no `scope` gets no org file, doc or cloud-fs access, and a job with no `scope` gets no org-fs mount from its user's bindings. |
| `access.org_data_no_user` | Org that owns the data | A job token for work no user started (event, schedule or system runs) gets no org file, doc or cloud-fs access. A workflow or pipeline step that such a run would create with org files, docs or cloud-fs in its declared `scope` is refused (400); its env-db entries stand. The orchestrator mounts no org files for such a job. |
| `access.org_data_scope_wide` | Org that owns the data | Each org file, doc or cloud-fs entry of a job scope a user declares (workflow and pipeline steps, retries), `*` included, must sit inside that user's role bindings (direct or through a group, org-wide or on the project); built-in roles do not count, except an org owner's or admin's. Otherwise 400. Pipeline steps gained the check in this release, so under `legacy` they are still not judged. |
| `access.org_data_scope_unjudged` | Org that owns the data | The orchestrator gives a job org files, docs or cloud-fs in its token scope or workspace only when the API judged the declared scope for the user who started the work (`jobs.token_scope_judged_at`); otherwise the job gets no org-fs mount and only the env-db part of its scope. |
| `access.org_data_role_wildcard` | Org that owns the data | A built-in project role (owner, admin, member), and the org `member` role, no longer carry a wildcard scope over the org's files, docs and cloud-fs mounts; their env-db scope stands. Members reach org data only through bindings. Org owners and admins keep theirs. |
| `access.org_data_route_scope` | Org that owns the data | Routes that name no single resource are held to what the caller reaches. For a job token with a declared `scope`: org doc search and stale listings, memory search and org search return only what the scope covers (org search also only the token's own project's attachments and events, and no org threads); agent KV (`/agents/<slug>/kv/<namespace>/<key>`) and thread distillation (the doc it writes) need a path inside the scope; org-fs device enrolment and changes to a link with no path are refused; cloud-fs mount listing and default-mount reads need a `cloud_fs` entry. For a person: mount listing and default-mount reads show only the mounts their grants reach. |
| `sso.session_origin` | Instance | The SSO's `/session` and `/logout` serve only the Eve dashboard (no `project_id`), the SSO itself for `/logout`, and an https host of the named project with `x-eve.auth` (default environment hosts, ingress aliases, verified custom domains, manifest `allowed_redirect_origins`). Any other origin, or none, gets 403. |
| `sso.app_access` | Instance | `/session` gives an app a token only for a person its app-access policy admits; anyone else gets 403. |
| `sso.audience_token` | Instance | An app gets a one-hour audience token (`aud` `eve-app:<project>[:<env>]`, no `orgs` claim) instead of the platform token. Under `audit` each app session that would get one is recorded. |
