/**
 * Security profiles decide what a hardening rule does:
 *
 * - `legacy`: today's behaviour; the rule is not checked.
 * - `audit`: today's behaviour, plus a finding recording what `strict`
 *   would refuse.
 * - `strict`: the rule is enforced (403), and the refusal is recorded.
 *
 * A profile is set on the instance, an org or a project. A project overrides
 * its org and an org overrides the instance. Each rule names whose profile
 * governs it: the side the rule protects (the instance for identity, the
 * project for its own resources, the org for org-wide data).
 */
export const SECURITY_PROFILES = ['legacy', 'audit', 'strict'] as const;

export type SecurityProfile = (typeof SECURITY_PROFILES)[number];

export type SecurityGoverningScope = 'instance' | 'org' | 'project';

/** Instance setting holding the instance profile. */
export const SECURITY_PROFILE_SETTING = 'security.profile';

/** Instance setting holding the profile written onto each new project. */
export const SECURITY_NEW_PROJECT_PROFILE_SETTING = 'security.new_project_profile';

export function isSecurityProfile(value: unknown): value is SecurityProfile {
  return typeof value === 'string' && (SECURITY_PROFILES as readonly string[]).includes(value);
}

/** The first valid profile of project, org and instance, else `legacy`. */
export function resolveSecurityProfile(levels: {
  project?: unknown;
  org?: unknown;
  instance?: unknown;
}): SecurityProfile {
  for (const value of [levels.project, levels.org, levels.instance]) {
    if (isSecurityProfile(value)) return value;
  }
  return 'legacy';
}
