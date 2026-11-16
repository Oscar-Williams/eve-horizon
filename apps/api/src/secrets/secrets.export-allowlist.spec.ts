import { ForbiddenException } from '@nestjs/common';
import { describe, expect, it, vi } from 'vitest';
import { ProjectSecretsController } from './secrets.controller';
import type { AuthUser } from '../auth/auth.types';

const RESTRICTED: AuthUser = {
  user_id: 'user_owner', is_job_token: true, job_id: 'opps-1', project_id: 'proj_opps',
  permissions: ['secrets:read'], secrets_allowlist: ['ANTHROPIC_API_KEY'],
} as AuthUser;

function controller() {
  const exportSafeSecrets = vi.fn(async (_p: string, keys: string[]) => keys.map((key) => ({ key, value: 'v' })));
  return { exportSafeSecrets, controller: new ProjectSecretsController({ exportSafeSecrets } as never) };
}

describe('POST /projects/:project_id/secrets/export', () => {
  it('refuses a restricted job token a key its allowlist leaves out', async () => {
    const { controller: c, exportSafeSecrets } = controller();

    await expect(c.exportSecrets('proj_opps', { keys: ['GHCR_TOKEN'] } as never, RESTRICTED)).rejects.toBeInstanceOf(ForbiddenException);
    expect(exportSafeSecrets).not.toHaveBeenCalled();
  });

  it('exports keys the allowlist names, and anything to an unrestricted caller', async () => {
    const { controller: c, exportSafeSecrets } = controller();

    await c.exportSecrets('proj_opps', { keys: ['ANTHROPIC_API_KEY'] } as never, RESTRICTED);
    await c.exportSecrets('proj_opps', { keys: ['GHCR_TOKEN'] } as never, { user_id: 'user_owner' } as AuthUser);

    expect(exportSafeSecrets).toHaveBeenCalledTimes(2);
  });
});
