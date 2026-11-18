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
