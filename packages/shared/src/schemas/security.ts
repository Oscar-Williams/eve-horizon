import { z } from 'zod';
import { SECURITY_PROFILES } from '../security/profile.js';

/**
 * Set a security profile. `instance` is the instance default; `new_projects`
 * is written onto each new project; `org` and `project` override the level
 * above. `null` clears an org or project override (or resets the instance and
 * new-project settings).
 */
export const SetSecurityProfileRequestSchema = z
  .object({
    scope: z.enum(['instance', 'new_projects', 'org', 'project']),
    id: z.string().trim().min(1).optional(),
    profile: z.enum(SECURITY_PROFILES).nullable(),
    /** Set the instance strict although v1 secrets or plain OAuth columns remain (otherwise 409). */
    force: z.boolean().optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if ((value.scope === 'org' || value.scope === 'project') && !value.id) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['id'], message: `scope ${value.scope} needs an id` });
    }
    if ((value.scope === 'instance' || value.scope === 'new_projects') && value.id) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['id'], message: `scope ${value.scope} takes no id` });
    }
  });

export type SetSecurityProfileRequest = z.infer<typeof SetSecurityProfileRequestSchema>;
