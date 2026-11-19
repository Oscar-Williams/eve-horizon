import { describe, expect, it, vi } from 'vitest';
import type { SecurityProfile } from '@eve/shared';
import { tokenScopeForJob } from './job-token-scope';

/**
 * Script and `run` action jobs mint their own job token from the job's
 * declared scope. They hold org data to the same decision as the
 * orchestrator (P1-6): a scope no user started, or one never judged for its
 * user, keeps its org files, docs and cloud-fs only when the org's profile
 * is not strict.
 */
const scope = { orgfs: { read_only_prefixes: ['/groups/**'] }, envdb: { schemas: ['public'] } };

function job(overrides: Record<string, unknown> = {}) {
  return {
    id: 'lab-1234abcd',
    project_id: 'proj_a',
    actor_user_id: 'user_pa',
    token_scope: scope,
    token_scope_judged_at: new Date('2026-11-19T00:00:00Z'),
    ...overrides,
  };
}

describe('tokenScopeForJob', () => {
  it('mints a judged scope a user started as it is', async () => {
    const decide = vi.fn(async (): Promise<SecurityProfile> => 'strict');
    await expect(tokenScopeForJob(job(), decide)).resolves.toEqual(scope);
    expect(decide).not.toHaveBeenCalled();
  });

  it('keeps only the env-db part under strict for work no user started', async () => {
    const decide = vi.fn(async (): Promise<SecurityProfile> => 'strict');
    await expect(tokenScopeForJob(job({ actor_user_id: null }), decide)).resolves.toEqual({ envdb: { schemas: ['public'] } });
    expect(decide).toHaveBeenCalledWith('access.org_data_no_user', expect.objectContaining({ governing: 'org', projectId: 'proj_a' }));
  });

  it('keeps only the env-db part under strict for a scope never judged', async () => {
    const decide = vi.fn(async (): Promise<SecurityProfile> => 'strict');
    await expect(tokenScopeForJob(job({ token_scope_judged_at: null }), decide)).resolves.toEqual({ envdb: { schemas: ['public'] } });
    expect(decide).toHaveBeenCalledWith('access.org_data_scope_unjudged', expect.anything());
  });

  it('mints the scope as it is under audit, having recorded it', async () => {
    const decide = vi.fn(async (): Promise<SecurityProfile> => 'audit');
    await expect(tokenScopeForJob(job({ token_scope_judged_at: null }), decide)).resolves.toEqual(scope);
    expect(decide).toHaveBeenCalledTimes(1);
  });

  it('mints no scope for a job without one, and refuses a scope that does not parse', async () => {
    const decide = vi.fn(async (): Promise<SecurityProfile> => 'strict');
    await expect(tokenScopeForJob(job({ token_scope: null }), decide)).resolves.toBeUndefined();
    await expect(tokenScopeForJob(job({ token_scope: { orgfs: 'everything' } }), decide)).resolves.toEqual({});
  });
});
