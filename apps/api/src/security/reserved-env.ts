import { profileHeldEnvKeys } from '@eve/shared';
import type { AuthUser } from '../auth/auth.types.js';
import type { SecurityService } from './security.service.js';

/** Security rule: env override names the project's strict profile reserves (governed by the project). */
export const RESERVED_ENV_RULE = 'harness.reserved_env';

/**
 * Hold env overrides a caller sends now (a job, a workflow invoke, chat
 * hints, a manifest sync) to the project's profile: code-loading names and
 * the added TLS trust names are refused (403) under `strict` and recorded
 * under `audit`. Names reserved on every profile are refused by the schema.
 */
export async function holdReservedEnvOverrides(
  security: SecurityService | undefined,
  ctx: { projectId: string; actor?: AuthUser | null; where: string },
  overrides: Record<string, string> | null | undefined,
): Promise<void> {
  const keys = profileHeldEnvKeys(overrides);
  if (keys.length === 0 || !security) return;
  await security.gate(
    RESERVED_ENV_RULE,
    {
      governing: 'project',
      projectId: ctx.projectId,
      actor: ctx.actor ?? null,
      detail: { keys: [...keys].sort().join(','), where: ctx.where },
    },
    `env_overrides ${keys.join(', ')} in ${ctx.where} are reserved under the project's strict profile`,
  );
}
