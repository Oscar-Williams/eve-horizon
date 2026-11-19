import { describe, expect, it, vi } from 'vitest';
import type { SecurityProfile } from '@eve/shared';
import { SecretsService } from './secrets.service';
import type { SecurityService } from '../security/security.service';
import type { AuthUser } from '../auth/auth.types';

/**
 * Rule secrets.job_org_write (P2-7, A3). The org secret routes already
 * refuse job and service tokens on every profile (org-settings spec). What
 * the rule adds is the harness credential write-back: work a job did may
 * update the credential only at project scope under a strict project. The
 * runner's credential route asks mayJobWriteSecret before it writes.
 */

const JOB: AuthUser = {
  user_id: 'user_alice', is_job_token: true, job_id: 'shop-7', project_id: 'proj_shop', org_id: 'org_acme',
  permissions: ['jobs:read'],
} as AuthUser;

function service(profile: SecurityProfile) {
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  process.env.EVE_SECRETS_MASTER_KEY = 'test-master-key';
  const decide = vi.fn(async () => profile);
  return { secrets: new SecretsService({} as never, { decide } as unknown as SecurityService), decide };
}

describe('secrets.job_org_write: a job writing a credential back', () => {
  it('may not write an org-scope secret under a strict project, and the refusal is recorded', async () => {
    const { secrets, decide } = service('strict');
    await expect(secrets.mayJobWriteSecret(JOB, 'org', 'CODEX_AUTH_JSON_B64')).resolves.toBe(false);
    expect(decide).toHaveBeenCalledWith('secrets.job_org_write', expect.objectContaining({
      governing: 'project', projectId: 'proj_shop', actor: JOB,
      detail: expect.objectContaining({ scope: 'org', key: 'CODEX_AUTH_JSON_B64' }),
    }));
  });

  it('may write it under audit, which records the write', async () => {
    const { secrets, decide } = service('audit');
    await expect(secrets.mayJobWriteSecret(JOB, 'org', 'CODEX_AUTH_JSON_B64')).resolves.toBe(true);
    expect(decide).toHaveBeenCalledTimes(1);
  });

  it('may always write a project-scope secret, and nothing is decided', async () => {
    const { secrets, decide } = service('strict');
    await expect(secrets.mayJobWriteSecret(JOB, 'project', 'CODEX_AUTH_JSON_B64')).resolves.toBe(true);
    expect(decide).not.toHaveBeenCalled();
  });

  it('judges a service token the same way', async () => {
    const { secrets } = service('strict');
    const serviceToken = { user_id: 'svc', is_service_token: true, service_name: 'api', project_id: 'proj_shop', org_id: 'org_acme' } as AuthUser;
    await expect(secrets.mayJobWriteSecret(serviceToken, 'org', 'SHOP_KEY')).resolves.toBe(false);
  });
});
