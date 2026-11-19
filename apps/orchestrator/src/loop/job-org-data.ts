import type { AccessBindingScope, SecurityGoverningScope, SecurityProfile } from '@eve/shared';
import { hasUserActor } from '@eve/shared';

/** A job token's scope was never judged against the user who started the work (P1-6). */
export const ORG_DATA_SCOPE_UNJUDGED_RULE = 'access.org_data_scope_unjudged';
/** Work no user started reached org files, docs or cloud-fs (P1-6). */
export const ORG_DATA_NO_USER_RULE = 'access.org_data_no_user';
/** A job with no scope reached org files, docs or cloud-fs (P1-6). */
export const ORG_DATA_UNSCOPED_RULE = 'access.org_data_unscoped';

export type DecideOrgDataRule = (
  rule: string,
  ctx: {
    orgId: string;
    projectId: string;
    governing: SecurityGoverningScope;
    actorType: string;
    actorId: string;
    detail: Record<string, string>;
  },
) => Promise<SecurityProfile>;

/** Whether a scope names org files, docs or cloud-fs (env-db is the project's own data). */
export function scopeReachesOrgData(scope: AccessBindingScope | null | undefined): boolean {
  if (!scope) return false;
  return Boolean(
    scope.orgfs?.allow_prefixes?.length
    || scope.orgfs?.read_only_prefixes?.length
    || scope.orgdocs?.allow_prefixes?.length
    || scope.orgdocs?.read_only_prefixes?.length
    || scope.cloud_fs?.allow_mount_ids?.length,
  );
}

/** A scope without its org files, docs and cloud-fs entries: only its env-db part stays. */
export function withoutOrgData(scope: AccessBindingScope): AccessBindingScope {
  return scope.envdb ? { envdb: scope.envdb } : {};
}

/**
 * The orchestrator's second line for org data in jobs (P1-6), before it
 * builds a job's org-fs mount and token scope. The API judges declared
 * scopes when it creates jobs; this decides, under the org's profile, the
 * cases it did not judge:
 *
 * - work no user started that carries org data in its scope;
 * - a scope never judged for the user who started the work (`token_scope_judged_at` unset);
 * - a job with no scope whose org-fs mount would come from its user's bindings.
 *
 * `strict` withholds the org data (`withhold`), `audit` records and keeps it,
 * `legacy` keeps it. A judged scope a user started is kept without deciding.
 */
export async function holdJobOrgData(params: {
  job: { id: string; project_id: string; actor_user_id?: string | null; token_scope_judged_at?: Date | null };
  orgId: string;
  tokenScope: AccessBindingScope | null;
  mountFromBindings: boolean;
  decide: DecideOrgDataRule;
}): Promise<'keep' | 'withhold'> {
  const { job, orgId, tokenScope, mountFromBindings, decide } = params;
  const actor = hasUserActor(job.actor_user_id) ? job.actor_user_id : null;
  let rule: string | null = null;
  if (tokenScope) {
    if (!scopeReachesOrgData(tokenScope)) return 'keep';
    rule = !actor ? ORG_DATA_NO_USER_RULE : !job.token_scope_judged_at ? ORG_DATA_SCOPE_UNJUDGED_RULE : null;
  } else if (mountFromBindings) {
    rule = actor ? ORG_DATA_UNSCOPED_RULE : ORG_DATA_NO_USER_RULE;
  }
  if (!rule) return 'keep';
  const profile = await decide(rule, {
    orgId,
    projectId: job.project_id,
    governing: 'org',
    actorType: actor ? 'user' : 'none',
    actorId: actor ?? 'none',
    detail: { job_id: job.id, stage: 'dispatch' },
  });
  return profile === 'strict' ? 'withhold' : 'keep';
}
