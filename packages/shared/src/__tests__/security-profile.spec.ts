import { describe, expect, it } from 'vitest';
import { isSecurityProfile, resolveSecurityProfile } from '../security/profile.js';

describe('resolveSecurityProfile', () => {
  it('takes the project profile first, then the org, then the instance', () => {
    expect(resolveSecurityProfile({ project: 'strict', org: 'legacy', instance: 'audit' })).toBe('strict');
    expect(resolveSecurityProfile({ project: null, org: 'legacy', instance: 'audit' })).toBe('legacy');
    expect(resolveSecurityProfile({ project: null, org: null, instance: 'audit' })).toBe('audit');
  });

  it('falls back to legacy when nothing is set', () => {
    expect(resolveSecurityProfile({})).toBe('legacy');
  });

  it('ignores values that are not profiles', () => {
    expect(resolveSecurityProfile({ project: 'STRICT', org: 'audit' })).toBe('audit');
    expect(resolveSecurityProfile({ project: '', org: undefined, instance: 'off' })).toBe('legacy');
  });

  it('recognises exactly the three profiles', () => {
    expect(['legacy', 'audit', 'strict'].every(isSecurityProfile)).toBe(true);
    expect(isSecurityProfile('enforce')).toBe(false);
    expect(isSecurityProfile(null)).toBe(false);
  });
});
