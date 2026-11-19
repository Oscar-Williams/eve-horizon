import { describe, expect, it } from 'vitest';
import type { SecretResolveItem } from '../../schemas/secret.js';
import {
  agentSecretsAllowlist,
  filterSecretsByAllowlist,
  narrowSecretsAllowlist,
} from '../secrets-allowlist.js';

function secret(key: string, scope_type: SecretResolveItem['scope_type'] = 'project'): SecretResolveItem {
  return { key, value: `${key}-value`, type: 'env_var', scope_type, scope_id: 'scope_1' } as SecretResolveItem;
}

const RESOLVED = [
  secret('ANTHROPIC_API_KEY', 'org'),
  secret('GITHUB_TOKEN', 'project'),
  secret('SHOP_SIGNING_KEY', 'project'),
  secret('PERSONAL_TOKEN', 'user'),
  secret('SMTP_PASSWORD', 'system'),
];

describe('narrowSecretsAllowlist', () => {
  it('leaves a job unrestricted when nothing declares an allowlist', () => {
    expect(narrowSecretsAllowlist(null, undefined)).toBeNull();
  });

  it('keeps the only declared allowlist', () => {
    expect(narrowSecretsAllowlist(['B', 'A'], null)).toEqual(['A', 'B']);
  });

  it('keeps only keys every declared allowlist names', () => {
    expect(narrowSecretsAllowlist(['A', 'B'], ['B', 'C'], null)).toEqual(['B']);
  });

  it('treats an empty allowlist as "no secrets", not as undeclared', () => {
    expect(narrowSecretsAllowlist([], ['A'])).toEqual([]);
  });
});

describe('filterSecretsByAllowlist', () => {
  it('passes every secret through when no allowlist is declared', () => {
    expect(filterSecretsByAllowlist(RESOLVED, null)).toEqual(RESOLVED);
    expect(filterSecretsByAllowlist(RESOLVED, undefined)).toEqual(RESOLVED);
  });

  it('keeps only allowlisted keys, whatever scope they come from', () => {
    const kept = filterSecretsByAllowlist(RESOLVED, ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY', 'NOT_SET']);
    expect(kept.map((s) => s.key)).toEqual(['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY']);
  });

  it('withholds every secret for an empty allowlist', () => {
    expect(filterSecretsByAllowlist(RESOLVED, [])).toEqual([]);
  });
});

describe('agentSecretsAllowlist', () => {
  it('reads access.secrets from an agent\'s stored access config', () => {
    expect(agentSecretsAllowlist({ permissions: ['jobs:read'], secrets: ['SHOP_SIGNING_KEY'] })).toEqual(['SHOP_SIGNING_KEY']);
  });

  it('is undeclared when the agent has no access.secrets', () => {
    expect(agentSecretsAllowlist(null)).toBeNull();
    expect(agentSecretsAllowlist({ envs: ['staging'] })).toBeNull();
  });

  it('fails closed on a malformed stored value', () => {
    expect(agentSecretsAllowlist({ secrets: 'SHOP_SIGNING_KEY' })).toEqual([]);
    expect(agentSecretsAllowlist({ secrets: ['OK', 7] })).toEqual(['OK']);
  });
});
