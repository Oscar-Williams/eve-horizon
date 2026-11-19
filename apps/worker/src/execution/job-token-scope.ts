import {
  AccessBindingScopeSchema,
  holdJobOrgData,
  withoutOrgData,
  type AccessBindingScope,
  type DecideOrgDataRule,
} from '@eve/shared';

/**
 * The scope a script or `run` action job mints its own token with: the
 * job's declared token scope, held to the same org data decision as the
 * orchestrator's (see holdJobOrgData). Under the org's strict profile a
 * scope no user started, or one never judged for its user, keeps only its
 * env-db part. A scope that does not parse reaches nothing.
 */
export async function tokenScopeForJob(
  job: {
    id: string;
    project_id: string;
    actor_user_id?: string | null;
    token_scope?: unknown;
    token_scope_judged_at?: Date | string | null;
  },
  decide: DecideOrgDataRule,
): Promise<AccessBindingScope | undefined> {
  if (job.token_scope === null || job.token_scope === undefined) return undefined;
  const parsed = AccessBindingScopeSchema.safeParse(job.token_scope);
  if (!parsed.success) return {};
  const scope = parsed.data;
  const held = await holdJobOrgData({ job, tokenScope: scope, mountFromBindings: false, decide });
  return held === 'withhold' ? withoutOrgData(scope) : scope;
}
