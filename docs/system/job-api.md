# Job API Specification

> Status: Current
> Last Updated: 2026-02-12
> Purpose: Define the primary Job API as the unified interface for all work in Eve Horizon.

## Overview

The Job API is the primary interface for creating, executing, and reviewing work in Eve Horizon. It provides:

- Job creation with a required description (the work prompt)
- Phase-based lifecycle (`idea → backlog → ready → active → review → done/cancelled`)
- Hierarchical jobs and dependency tracking
- Claim/release workflow for execution attempts
- Review workflow (submit, approve, reject)

**Note**: "Job" refers to Eve Horizon's user-facing work unit. "Task" refers to cc-mirror sub-agent coordination within a job.

## Current (Implemented)

- Project-scoped job endpoints (create, list, ready, blocked)
- Job-scoped endpoints (get, update, tree, dependencies)
- Claim/release workflow and attempts
- Review workflow (submit/approve/reject)
- Attempt creation, continuation, and logs
- Execution receipts (per-attempt cost + timing)
- Durable script/action-run execution: worker script and `action: { type: run }`
  jobs quick-ack submission, stream output into attempt logs, and complete via
  `runner.completed` / `runner.failed` events.

## Planned (Not Implemented)

- Automated scheduling decisions in the orchestrator (beyond manual phase transitions)
- UI for review and execution monitoring
- Workspace reuse/session modes (see `docs/system/job-git-controls.md`)
- Job harness options (model, variant, reasoning effort) and project harness policies. See `docs/system/harness-policy.md`.

## Legacy (Removed)

- Workflow-first APIs and workflow-scoped job definitions
- Numeric, project-scoped job IDs

## Identifiers

Eve Horizon uses a hybrid ID scheme:
- **Global entities** (org, project): TypeIDs for uniqueness and sortability
- **Jobs**: slug-based hierarchical IDs for readability
- **Attempts**: UUIDs plus per-job attempt numbers

### TypeID Format

```
{type}_{base32_timestamp_random}
```

Example: `proj_01abc...`

### Organization ID

```
org_01xyz...
```

### Project ID + Slug

```
proj_01abc...
```

- Projects also have a `slug` (4-8 chars, e.g., `MyProj`) used for job IDs.
  Slugs are unique within an org ignoring case (`MyProj` and `myproj` cannot
  both exist), because Kubernetes namespaces are built from the lower-cased
  slug; creating a case variant of an existing slug answers `409`.

### Job ID

Jobs use slug-based hierarchical IDs:

| Context | Format | Example |
| --- | --- | --- |
| Root job | `{slug}-{hash8}` | `myproj-a3f2dd12` |
| Child job | `{parent}.{n}` | `myproj-a3f2dd12.1` |

- Root IDs include the project slug plus an 8-char hash.
- Child IDs append a numeric suffix to the parent.
- Max depth: 3 levels.

### Attempt ID

- Attempts have a UUID `id` plus a job-scoped `attempt_number` (1, 2, 3...).
- API/CLI reference attempts by job ID + `attempt_number`.

## API Endpoints

```
# Project-scoped jobs
POST /projects/{project_id}/jobs             # Create job
GET  /projects/{project_id}/jobs             # List jobs
GET  /projects/{project_id}/jobs/ready       # Ready/schedulable jobs
GET  /projects/{project_id}/jobs/blocked     # Blocked jobs

# Admin jobs (cross-project)
GET  /jobs                                    # List jobs (admin view)

# Job-scoped operations
GET   /jobs/{job_id}                         # Get job
PATCH /jobs/{job_id}                         # Update job
GET   /jobs/{job_id}/tree                    # Job hierarchy
GET   /jobs/{job_id}/context                 # Job context + derived status
GET   /jobs/{job_id}/dependencies            # Dependencies
POST  /jobs/{job_id}/dependencies            # Add dependency
DELETE /jobs/{job_id}/dependencies/{related_job_id}

# Claim/release + attempts (job-scoped)
POST /jobs/{job_id}/claim                     # Claim (creates attempt)
POST /jobs/{job_id}/release                   # Release attempt
GET  /jobs/{job_id}/attempts                  # List attempts
GET  /jobs/{job_id}/attempts/{attempt_num}/logs
GET  /jobs/{job_id}/attempts/{attempt_num}/stream  # SSE logs for attempt

# Review workflow
POST /jobs/{job_id}/submit                    # Submit for review
POST /jobs/{job_id}/approve                   # Approve review
POST /jobs/{job_id}/reject                    # Reject review

# Job execution helpers (job-scoped)
GET  /jobs/{job_id}/result                   # Latest or attempt-specific result
GET  /jobs/{job_id}/wait                     # Wait for completion
GET  /jobs/{job_id}/stream                   # SSE logs for job
GET  /jobs/{job_id}/receipt                  # Latest or attempt-specific receipt
GET  /jobs/{job_id}/attempts/{attempt_id}/receipt
GET  /jobs/{job_id}/compare                  # Compare two attempts (a,b)
```

## Core Entities

```
Job -> JobAttempt -> Session -> ExecutionProcess
```

- **Job**: The logical unit of work (ID: `myproj-a3f2dd12`)
- **JobAttempt**: An isolated execution run (UUID + `attempt_number`)
- **Session**: Tracks executor and allows follow-up within an attempt
- **ExecutionProcess**: A single harness invocation within a session

## Execution Durability

Agent, script, and pipeline `action: { type: run }` jobs do not hold one
orchestrator-to-worker HTTP request open for the full command duration. The
orchestrator submits the job, receives a short `202 Accepted`, then polls runner
events for the terminal result.

For workflow/pipeline script jobs, `script_timeout_seconds` is the
authoritative execution ceiling. For pipeline `action: { type: run }`, the
action input `timeout_seconds` or `timeout` is used first, then
`hints.timeout_seconds`, then the platform default. Bash stdout/stderr are
written incrementally to execution logs, so `eve job follow` can show output
while the command is still running.

## Create Job

### Request

```typescript
interface CreateJobRequest {
  // Required
  description: string;             // Work prompt

  // Optional
  title?: string;                  // Auto-generated from description if omitted
  issue_type?: string;             // task, bug, feature, epic, chore
  labels?: string[];
  phase?: 'idea' | 'backlog' | 'ready' | 'active' | 'review' | 'done' | 'cancelled';
  priority?: number;               // 0-4 (default: 2)
  assignee?: string | null;
  review_required?: 'none' | 'human' | 'agent';
  parent_id?: string | null;
  defer_until?: string | null;     // ISO 8601
  due_at?: string | null;          // ISO 8601

  // Scheduling hints
  hints?: {
    harness?: string;              // e.g., "mclaude:fast"
    worker_type?: string;          // e.g., "default", "gpu"
    permission_policy?: string;    // yolo (default), auto_edit, never
    timeout_seconds?: number;
    resource_class?: string;       // compute SKU (runner sizing + accounting)
    max_cost?: { currency: string; amount: number }; // budget cap
    max_tokens?: number;           // token budget cap
  };

  // Git + workspace controls
  git?: {
    ref?: string;                   // Branch, tag, or SHA
    ref_policy?: 'auto' | 'env' | 'project_default' | 'explicit';
    branch?: string;
    create_branch?: 'never' | 'if_missing' | 'always';
    commit?: 'never' | 'manual' | 'auto' | 'required';
    commit_message?: string;
    push?: 'never' | 'on_success' | 'required';
    remote?: string;
  };
  workspace?: {
    mode?: 'job' | 'session' | 'isolated';
    key?: string;
  };

  // Execution targeting
  env_name?: string | null;         // Target environment (for env-based ref resolution)
  execution_mode?: 'persistent' | 'ephemeral';
}
```

### Response

```typescript
interface JobResponse {
  id: string;                       // Job ID (e.g., myproj-a3f2dd12)
  project_id: string;               // TypeID
  parent_id?: string | null;
  depth: number;
  title: string;
  description: string | null;
  issue_type: string;
  labels: string[];
  phase: string;
  priority: number;
  assignee?: string | null;
  review_required: string;
  review_status?: string | null;
  reviewer?: string | null;
  defer_until?: string | null;
  due_at?: string | null;
  hints?: Record<string, unknown>;
  git?: Record<string, unknown> | null;
  resolved_git?: {                    // Resolved git metadata from latest successful attempt
    resolved_ref?: string;             // e.g., "refs/heads/main"
    resolved_sha?: string;             // 40-char commit SHA that was checked out
    resolved_branch?: string;          // Branch name used
    ref_source?: string;               // How ref was resolved: env_release|manifest|project_default|explicit
    pushed?: boolean;                  // Whether changes were pushed back
    commits?: string[];                // Commit SHAs created during execution
  };
  workspace?: Record<string, unknown> | null;
  env_name?: string | null;
  execution_mode?: 'persistent' | 'ephemeral';
  created_at: string;
  updated_at: string;
  closed_at?: string | null;
  close_reason?: string | null;
}
```

**Budget hints:** When job admission is blocked by budget or suspension checks,
the API may populate `hints.budget_blocked` and `hints.budget_blocked_reason`.

### Minimal Example

```json
{
  "description": "Fix the login bug on mobile"
}
```

**Manifest defaults**: If the project has a synced manifest, `x-eve.defaults` is merged on create (env/hints/git/workspace). Explicit job fields override defaults.

## Update Job

Jobs are updated via `PATCH /jobs/{job_id}` with any subset of updatable fields.
Phase transitions are validated server-side.

```typescript
interface UpdateJobRequest {
  title?: string;
  description?: string | null;
  labels?: string[];
  phase?: 'idea' | 'backlog' | 'ready' | 'active' | 'review' | 'done' | 'cancelled';
  priority?: number;
  assignee?: string | null;
  review_required?: 'none' | 'human' | 'agent';
  defer_until?: string | null;
  due_at?: string | null;
  close_reason?: string | null;
  hints?: {
    harness?: string;
    worker_type?: string;
    permission_policy?: string;
    timeout_seconds?: number;
    resource_class?: string;
    max_cost?: { currency: string; amount: number };
    max_tokens?: number;
  };
  git?: {
    ref?: string;
    ref_policy?: 'auto' | 'env' | 'project_default' | 'explicit';
    branch?: string;
    create_branch?: 'never' | 'if_missing' | 'always';
    commit?: 'never' | 'manual' | 'auto' | 'required';
    commit_message?: string;
    push?: 'never' | 'on_success' | 'required';
    remote?: string;
  };
  workspace?: {
    mode?: 'job' | 'session' | 'isolated';
    key?: string;
  };
  env_name?: string | null;
  execution_mode?: 'persistent' | 'ephemeral';
}
```

## Review Workflow

- `submit`: requires `summary`
- `approve`: optional `comment`
- `reject`: requires `reason`

The decider of an approve or reject is the authenticated caller, recorded as
the job's `reviewer` and in the audit log; a `reviewer_id` in the body is
ignored. A person's own token is recorded as their user id; a job token as
`job:<job id>`, never as the person the job runs as; a service, service-principal
or app-link token as its kind and id (`service:<name>`, and so on). A `PATCH`
that moves a job from `review` to `done` is an approval too: it records the
caller as the decider, sets `review_status` to `approved` and writes the same
audit entry as the approve route. One that moves it back to `active` is a
rejection, as the reject route makes it: `review_status` becomes `rejected`, a
new attempt runs the job again, and a caller's secrets allowlist narrows the
job. A `PATCH` is applied only to the job state it was judged on: when the
job's phase, review requirement or actor changes before it is applied, it is
refused with 409.

A review is decided once. An approve, a reject or a `PATCH` that settles a
review holds the job's row while it decides; a second decision, made after the
first or racing it, finds the review decided and gets 409 ("already
decided"). It changes nothing: a reject that loses creates no new attempt. A
decision on a job that was never sent for review still gets 400.

Under the project's `strict` security profile (rule `jobs.approve_token`), only
a person's own token may approve or reject: job, service, service-principal and
app-link tokens get 403 (under `audit` they are allowed and recorded). On a
workflow or pipeline run step the person must also be the run's actor or a
project admin (rule `jobs.run_step_change`), so a step cannot approve itself or
another step of its run. A `PATCH` that settles a review counts as a decision
for both rules: moving a job out of `review` (to `done` approves, back to
`active` rejects, to `cancelled` cancels), changing `review_required` while the
job is in review, and lowering `review_required` (`human`, then `agent`, then
`none`) in any phase. A job token of a compiled workflow or pipeline step may
not lower `review_required` on any job, its own included (rule
`jobs.run_step_change`).

## Job Actor on Update

A job runs as its actor (`actor_user_id`): their user-scope secrets, org-fs
bindings and job-token permission ceiling. When someone other than the actor
uses `PATCH /jobs/{job_id}` to change what the job runs or how (`title`, which
opens the agent's prompt, `description`, `labels`, where `chat` sends the run's
output to the thread its hints name, `assignee`, `harness`, `harness_profile`,
`harness_options`, `hints`, `git`, `workspace`, `env_name`, `execution_mode`,
`defer_until`, or moving it to `ready` or `active`), they become the actor, and
an org-bound token's edit marks the job to resolve no user-scope secrets. The
job-token permissions the job already carries must be ones the new actor could
grant, and the new actor must hold every resource its token scope names (the
org-fs and org-docs prefixes, cloud-fs mounts and env-db schemas and tables, as
on workflow invoke and retry); work no user started cannot take on a scope
judged for a person. Otherwise the update is refused with 400 and nothing
changes. The actor's own edits, and cosmetic edits (`priority`, `due_at`,
`review_required`, `close_reason`, or moving the job to any other phase), keep
the actor.

The jobs of a workflow or pipeline run never change actor: the run's root (a
job with steps the run compiled under it) and each compiled step (its
`step_name` is set by the workflow or pipeline expander, which no route can
change). Only their actor can change what they run or their attachments;
anyone else is refused with 403, which names the way on: retry the workflow
(`eve workflow retry`) for a workflow's jobs, or start a new pipeline run
(`eve pipeline run`) for a pipeline step. Either runs as them. Cosmetic edits by
others still apply.

No actor and the `system` actor that job tokens carry for work no user started
are the same actor. Jobs that such work creates (job and batch create, workflow
invoke and retry, pipeline expansion) store no actor (`actor_user_id` null),
never the text `system`; rows written before 0.1.329 may still hold it, and
read the same. An edit by such a token to a job no user started keeps the
job as it is, and work no user started that becomes the actor of a person's job
is recorded as no actor, never as `system`.

Under the project's `strict` security profile (rule `jobs.run_step_change`),
the jobs of a run change only through the run. Changes to what they run, moves
to another phase (including `done` and `cancelled`), `review_required` changes,
claim, release, submit, approve and reject are accepted only from the run's
actor with their own user token (whoever started the run, or the retry the step
belongs to), a job token of one of the run's compiled steps, or a project admin
(`jobs:admin`). Anyone else gets 403, including the actor's agents outside the
run and a no-user token of another run. Under `audit` the change is allowed and
recorded as a finding. Under `strict`, cancelling a compiled step also cancels
the steps of its own run that depend on it, transitively; edges to jobs outside
the run are not followed.

The body is validated against `UpdateJobRequest` (for example `title` is at
most 500 characters and `priority` is 0-4); an invalid body is refused with 400.

An update is applied in one transaction: the actor, the phase and the fields
change together, or, when any part fails (an invalid phase transition, say),
nothing changes. An edit that changes what the job runs is judged against the
actor the job had when it was read; if the actor changed before the edit is
applied, the edit is refused with 409 and the caller should read the job again
and retry.

Adding or removing a job attachment (`POST /jobs/{job_id}/attachments`,
`DELETE /jobs/{job_id}/attachments/{att_id}`) is judged the same way: on the
jobs of a run only the actor may do it (403 otherwise); on other jobs someone
other than the actor becomes the actor (400 if they could not grant the job's
permissions or hold its token scope, 409 if the actor changed after the job was
read), and the attachment and actor change together or not at all. The actor's
own attachments, including an agent attaching to its own job, keep the actor.

A job's attachments are taken in by other jobs, not by the job itself: a child
job copies named parent attachments (`agent_context.parent_attachments`) into
`.eve/context/parent/`, and a `job_attachments:/<job-id>/<name>` resource ref
writes one into `.eve/resources/`. A job takes in only attachments its own
actor created (`created_by`); a job no user started takes in only attachments
created by work no user started. Others are skipped with a logged reason (a
skipped resource ref is reported as `resource_access_denied`).

## Dependency Model

Dependencies are stored as relations between jobs (`blocks`, `conditional_blocks`, `waits_for`, etc.).
The CLI uses `job dep add|remove|list` to manage these relations.

Jobs are linked only within one project: a `parent_id` on create, or a
`related_job_id` on `POST /jobs/{job_id}/dependencies`, must name a job in the
same project (403 otherwise, 404 if it does not exist). Dependencies, context
(parent, siblings, children) and the tree only ever list jobs from the job's own
project.

A job created with `parent_id` joins its parent's tree (its coordination
thread, its run, and the wake-ups of a parent waiting on its children), so only
callers the parent already belongs to may create one: the parent's actor (with
their own token or their agents' job tokens); for a job token of work no user
started, the parent job itself or a job of the parent's run (its root or one of
its compiled steps, judged from the job records); or a project admin
(`jobs:admin`). Anyone else gets 403.

The dependencies of a compiled workflow or pipeline step (`step_name` set) come
from its definition: adding or removing one through the dependency routes is
refused with 409. Adding or removing a dependency of a run root is held to rule
`jobs.run_step_change` like any other change to it. For a job outside any run,
rule `jobs.dependency_change` holds it to the job's actor (or their agents), the
job's own token, or a project admin. Under `strict`, a compiled step's failure
cancels only the steps of its own run that depend on it.

Workflow invocation creates every step in `backlog`, wires all blocking
relations, then releases the complete graph to `ready`. A wiring failure does
not release any steps. Independent steps can then start while dependent steps
wait for their blockers; roots cannot finish during partial graph creation.

Jobs can have blocking dependencies:

- `blocked_by[]`: Job IDs that must complete before this can start
- `blocks[]`: Convenience to set reverse relationship (updates blocking jobs)
- Scheduler respects `blocked_by` when selecting ready jobs

Example:
```json
{
  "description": "Deploy to staging",
  "blocked_by": ["myproj-a3f2dd12", "myproj-b4e3cc21"]
}
```

The new job cannot start until both blocking jobs are Done.

## Review Workflow Examples

Approval:
```json
{
  "comment": "Approved, please proceed with the implementation"
}
```

Rejection:
```json
{
  "reason": "Please add error handling for the network timeout case"
}
```

## Execution Receipts

Each job attempt can include a persisted receipt with timing and cost details.
Receipts are assembled from `execution_logs` events (including `llm.call` usage)
and stored on the attempt.

Endpoints:

```
GET /jobs/{job_id}/receipt                         # Latest or attempt-specific (via ?attempt=N)
GET /jobs/{job_id}/attempts/{attempt_id}/receipt   # Receipt by attempt id
GET /jobs/{job_id}/compare?a=1&b=2                 # Compare two attempts
```

Receipts include:

- `timing` (billable ms, phase durations)
- `llm` usage totals (input/output/cache/reasoning tokens)
- `auth` — the credential the harness selected (`harness`, `source`,
  `secret_key`, `scope_type`, `scope_id`; key name and scope only, never a
  value), read from the attempt's `claude_auth_selected` /
  `codex_auth_selected` log; `null` when no selection was logged
- `base_cost_usd` and `billed_cost` totals

## Job Hierarchy

Jobs can form parent-child relationships via `parent_id`:

- Child jobs use `{parent}.{n}` ID format (e.g., `myproj-a3f2dd12.1`)
- Max depth: 3 levels
- Enables "spawn sub-job from current work" pattern

Example:
```json
{
  "description": "Implement the authentication module",
  "parent_id": "myproj-a3f2dd12"
}
```

## Scheduling Behavior

Selection order for ready jobs:

```
1. Filter: phase = ready AND blocked_by all done
2. Sort: priority (0 highest, 4 lowest)
3. Sort: created_at (FIFO within priority)
```

## Session Continuity

1. **attempt\_id** is the stable identifier for job work
2. **session\_id** is the harness-level session (may change on reconstruction)
3. Continue endpoint routes to correct workspace via `attempt_id`
4. System auto-detects initial vs follow-up based on existing `agent_session_id`
5. Each new attempt creates a new workspace (isolated git branch/container)

If a worker is recycled:
- Workspace can be reconstructed from stored invocations
- Session ID may change, but attempt_id remains stable
- Prompts are replayable for reconstruction

## Attempt Git Metadata

Attempt responses include a `git` object when git controls are used, populated from `job_attempts.git_json`:

```json
{
  "git": {
    "resolved_ref": "refs/heads/main",
    "resolved_sha": "abc123",
    "resolved_branch": "job/myproj-a3f2dd12",
    "ref_source": "env_release|manifest|project_default|explicit",
    "pushed": true,
    "commits": ["def456"]
  }
}
```

## Job Result API

### Get Job Result

Fetch the result of a completed job.

**Endpoint:** `GET /jobs/{job_id}/result`

**Query Parameters:**
- `attempt` (optional): Specific attempt number. If omitted, returns the latest attempt's result.
- `format` (optional): Output format - `text`, `json`, or `full` (default: `full`)

**CLI Example:**
```bash
# Get latest result with full formatting
eve job result myproj-a3f2dd12

# Get text-only output
eve job result myproj-a3f2dd12 --format text

# Get result from specific attempt
eve job result myproj-a3f2dd12 --attempt 2 --format json
```

### Wait for Job Completion

Block until a job completes or times out. Uses Server-Sent Events (SSE) to stream status updates.

**Endpoint:** `GET /jobs/{job_id}/wait`

**Query Parameters:**
- `timeout` (optional): Timeout in seconds (default: 300, max: 300)
- `quiet` (optional): Suppress progress output
- `json` (optional): Return JSON output format

**CLI Example:**
```bash
# Wait for job to complete (default 300s timeout)
eve job wait myproj-a3f2dd12

# Wait with custom timeout
eve job wait myproj-a3f2dd12 --timeout 120

# Wait quietly with JSON output (useful in scripts)
eve job wait myproj-a3f2dd12 --quiet --json
```

**Exit Codes:**
- `0`: Job completed successfully
- `1`: Job failed
- `124`: Timeout reached
- `125`: Job was cancelled

### Stream Job Logs

Stream job logs in real-time using Server-Sent Events (SSE).

**Endpoint:** `GET /jobs/{job_id}/stream`

**Query Parameters:**
- `raw` (optional): Return raw JSON lines instead of formatted output
- `no-result` (optional): Don't include final result when job completes

**CLI Example:**
```bash
# Stream logs with formatted output
eve job follow myproj-a3f2dd12

# Stream raw JSON (for parsing)
eve job follow myproj-a3f2dd12 --raw | jq '.tool'

# Filter logs by tool using raw mode
eve job follow myproj-a3f2dd12 --raw | jq 'select(.tool == "bash")'
```
