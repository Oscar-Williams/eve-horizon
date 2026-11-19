import { describe, expect, it, vi } from 'vitest';
import type { SecurityProfile } from '@eve/shared';
import { holdJobOrgData, withoutOrgData } from './job-org-data';

/**
 * The orchestrator's second line for org data in jobs (P1-6): before it
 * builds a job's org-fs mount and token scope it decides, under the org's
 * profile, whether org data may reach a job whose scope was never judged,
 * that no user started, or that carries no scope at all.
 */
function job(overrides: Record<string, unknown> = {}) {
  return {
    id: 'lab-1234abcd',
    project_id: 'proj_a',
    actor_user_id: 'user_pa',
    token_scope_judged_at: new Date('2026-11-19T00:00:00Z'),
    ...overrides,
  };
}

const orgScope = { orgfs: { read_only_prefixes: ['/groups/**'] }, envdb: { schemas: ['public'] } };

function decider(profile: SecurityProfile) {
  return vi.fn(async () => profile);
}

describe('holdJobOrgData', () => {
  it('keeps a judged scope a user started without deciding anything', async () => {
    const decide = decider('strict');
    await expect(holdJobOrgData({ job: job(), orgId: 'org_a', tokenScope: orgScope, mountFromBindings: false, decide }))
      .resolves.toBe('keep');
    expect(decide).not.toHaveBeenCalled();
  });

  it('withholds org data under strict for work no user started', async () => {
    const decide = decider('strict');
    await expect(holdJobOrgData({ job: job({ actor_user_id: null }), orgId: 'org_a', tokenScope: orgScope, mountFromBindings: false, decide }))
      .resolves.toBe('withhold');
    expect(decide).toHaveBeenCalledWith('access.org_data_no_user', expect.objectContaining({ orgId: 'org_a', governing: 'org', actorType: 'none' }));
  });

  it('withholds a scope that was never judged under strict', async () => {
    const decide = decider('strict');
    await expect(holdJobOrgData({ job: job({ token_scope_judged_at: null }), orgId: 'org_a', tokenScope: orgScope, mountFromBindings: false, decide }))
      .resolves.toBe('withhold');
    expect(decide).toHaveBeenCalledWith('access.org_data_scope_unjudged', expect.objectContaining({ actorType: 'user', actorId: 'user_pa' }));
  });

  it('withholds a mount taken from bindings for a job with no scope under strict', async () => {
    const decide = decider('strict');
    await expect(holdJobOrgData({ job: job(), orgId: 'org_a', tokenScope: null, mountFromBindings: true, decide }))
      .resolves.toBe('withhold');
    expect(decide).toHaveBeenCalledWith('access.org_data_unscoped', expect.anything());
  });

  it('keeps everything under audit, having recorded it', async () => {
    const decide = decider('audit');
    await expect(holdJobOrgData({ job: job({ actor_user_id: null }), orgId: 'org_a', tokenScope: orgScope, mountFromBindings: false, decide }))
      .resolves.toBe('keep');
    expect(decide).toHaveBeenCalledTimes(1);
  });

  it('decides nothing when no org data is in play', async () => {
    const decide = decider('strict');
    await expect(holdJobOrgData({ job: job({ actor_user_id: null }), orgId: 'org_a', tokenScope: { envdb: { schemas: ['public'] } }, mountFromBindings: false, decide }))
      .resolves.toBe('keep');
    await expect(holdJobOrgData({ job: job(), orgId: 'org_a', tokenScope: null, mountFromBindings: false, decide }))
      .resolves.toBe('keep');
    expect(decide).not.toHaveBeenCalled();
  });
});

describe('withoutOrgData', () => {
  it('keeps only the env-db part of a scope', () => {
    expect(withoutOrgData(orgScope)).toEqual({ envdb: { schemas: ['public'] } });
    expect(withoutOrgData({ cloud_fs: { allow_mount_ids: ['*'] } })).toEqual({});
  });
});
