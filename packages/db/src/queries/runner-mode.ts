import type { Db } from '../client.js';
import { generateSecurityFindingId, type SecurityProfile } from '@eve/shared';
import { governingSecurityProfile, securityQueries } from './security.js';

/** Project rule: job code runs only in credential-free runner pods. */
export const RUNNER_MODE_RULE = 'isolation.runner_mode';

/**
 * The instance switch EVE_RUNNER_PODS_ONLY: no job code in the worker or the
 * agent runtime, whatever the profile. Unlike EVE_SCRIPT_K8S_RUNNER (scripts
 * only), it covers agent jobs, script steps and `action: run`, and refuses
 * legacy pipeline `run` steps.
 */
export function runnerPodsOnly(env: NodeJS.ProcessEnv = process.env): boolean {
  const value = env.EVE_RUNNER_PODS_ONLY?.trim().toLowerCase();
  return value === 'true' || value === '1';
}

export interface RunnerModeDecision {
  /** The project's profile for isolation.runner_mode (stamps honoured). */
  profile: SecurityProfile;
  /** The instance switch is set. */
  podsOnly: boolean;
  /** Job code must run in a runner pod: strict, or the switch. */
  required: boolean;
}

/** Where a project's job code must run. Records nothing. */
export async function runnerModeFor(db: Db, projectId: string): Promise<RunnerModeDecision> {
  const profile = await governingSecurityProfile(db, { projectId, governing: 'project', rule: RUNNER_MODE_RULE });
  const podsOnly = runnerPodsOnly();
  return { profile, podsOnly, required: podsOnly || profile === 'strict' };
}

/**
 * Record an isolation.runner_mode finding: an inline run under `audit` (the
 * evidence a project needs before strict), or a refusal under `strict`.
 * Never fails the work.
 */
export async function recordRunnerModeFinding(
  db: Db,
  finding: { projectId: string; profile: SecurityProfile; actorId: string; detail: Record<string, string | number | boolean | null> },
): Promise<void> {
  if (finding.profile === 'legacy') return;
  try {
    const security = securityQueries(db);
    const row = await security.getProfiles({ projectId: finding.projectId });
    await security.recordFinding({
      id: generateSecurityFindingId(),
      rule: RUNNER_MODE_RULE,
      profile: finding.profile,
      org_id: row?.org_id ?? null,
      project_id: finding.projectId,
      actor_type: 'job',
      actor_id: finding.actorId,
      detail: finding.detail,
    });
  } catch {
    // A finding is evidence, not a control.
  }
}
