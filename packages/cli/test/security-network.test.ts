import { describe, expect, it } from 'vitest';
import { describeNetworkReconcile, describePolicyEnforcement, describeStrictChecklist } from '../src/commands/security';

/**
 * `eve doctor security` and `eve system security reconcile` for
 * egress.default_deny: whether the cluster enforces NetworkPolicy, what each
 * project still needs before `strict`, and what reconcile wrote.
 */
describe('security network output', () => {
  it('says plainly when egress rules are not effective', () => {
    expect(describePolicyEnforcement({ policy_enforced: true, egress_effective: true })).toBe('enforced');
    expect(describePolicyEnforcement({ policy_enforced: false, egress_effective: false }))
      .toMatch(/not enforced: egress rules are not effective/);
    expect(describePolicyEnforcement({ policy_enforced: null, egress_effective: false }))
      .toMatch(/unknown.*network\.policy_enforced/);
    expect(describePolicyEnforcement(undefined)).toBeNull();
  });

  it('shows a project ready for strict, or what holds it back', () => {
    expect(describeStrictChecklist({ clean: true, blockers: [] })).toBe('ready for strict');
    expect(describeStrictChecklist({ clean: false, blockers: ['2 finding(s) in the last 14 days', 'network.policy_enforced is not true'] }))
      .toBe('not ready: 2 finding(s) in the last 14 days; network.policy_enforced is not true');
    expect(describeStrictChecklist(undefined)).toBe('');
  });

  it('summarises what network reconcile wrote and what failed', () => {
    const lines = describeNetworkReconcile({
      environments: { reconciled: 3, without_namespace: 1, applied: 4, removed: 2, failed: [{ environment_id: 'env_a', error: 'forbidden' }] },
      runners: { projects: 2, applied: 2, removed: 1, orphans_removed: 1, failed: [] },
    });
    expect(lines).toEqual([
      'Egress policies:',
      '  environments: 3 reconciled, 1 without a namespace, 4 written, 2 removed, 1 failed',
      '    env_a: forbidden',
      '  runner policies: 2 project(s), 2 written, 1 removed, 1 of deleted projects removed, 0 failed',
    ]);
  });
});
