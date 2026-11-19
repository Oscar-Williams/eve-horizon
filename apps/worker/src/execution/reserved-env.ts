import { decideSecurityRule, type Db } from '@eve/db';
import { alwaysRefusedEnvKeys, hasUserActor, profileHeldEnvKeys } from '@eve/shared';

/**
 * Reserved env override names a stored script or action job carries are
 * recorded under the project's profile (rule harness.reserved_env). True
 * under `strict`, when the run strips the names the profile holds as well as
 * those reserved on every profile.
 */
export async function reservedEnvOverridesStrict(
  db: Db,
  job: { id: string; project_id: string; actor_user_id?: string | null; env_overrides?: Record<string, string> | null },
): Promise<boolean> {
  const overrides = job.env_overrides ?? null;
  const keys = [...new Set([...alwaysRefusedEnvKeys(overrides), ...profileHeldEnvKeys(overrides)])].sort();
  if (keys.length === 0) return false;
  const actorUserId = hasUserActor(job.actor_user_id) ? job.actor_user_id! : null;
  const profile = await decideSecurityRule(db, 'harness.reserved_env', {
    projectId: job.project_id,
    governing: 'project',
    actorType: actorUserId ? 'user' : 'none',
    actorId: actorUserId ?? 'none',
    detail: { job_id: job.id, keys: keys.join(',') },
  });
  return profile === 'strict';
}
