import { describe, expect, it } from 'vitest';
import {
  mintRegistryPullCredential,
  mintRegistryPushCredential,
  REGISTRY_INTERNAL_KEY_VERSION,
  REGISTRY_PUSH_CREDENTIAL_TTL_SECONDS,
  registryCredentialKey,
  registryKeyVersion,
  verifyRegistryPullCredential,
  verifyRegistryPushCredential,
} from '../registry-pull-credential.ts';

const KEY = 'internal-key';
const CLAIMS = { projectId: 'proj_abc', environmentId: 'env_test', namespace: 'eve-acme-shop-test', epoch: 3 };

describe('registry pull credential', () => {
  it('round-trips its claims under the same key', () => {
    const credential = mintRegistryPullCredential(CLAIMS, KEY);
    expect(credential.startsWith('evepull1.')).toBe(true);
    expect(verifyRegistryPullCredential(credential, KEY)).toEqual(CLAIMS);
  });

  it('never contains the internal key', () => {
    const credential = mintRegistryPullCredential(CLAIMS, KEY);
    expect(credential).not.toContain(KEY);
    expect(Buffer.from(credential.split('.')[1], 'base64url').toString('utf8')).not.toContain(KEY);
  });

  it('is rejected under a different (rotated) key', () => {
    const credential = mintRegistryPullCredential(CLAIMS, KEY);
    expect(verifyRegistryPullCredential(credential, 'rotated-key')).toBeNull();
  });

  it('is rejected when the claims are altered', () => {
    const [prefix, , mac] = mintRegistryPullCredential(CLAIMS, KEY).split('.');
    const forged = Buffer.from(
      JSON.stringify({ p: 'proj_other', e: CLAIMS.environmentId, ns: CLAIMS.namespace, n: CLAIMS.epoch }),
    ).toString('base64url');
    expect(verifyRegistryPullCredential(`${prefix}.${forged}.${mac}`, KEY)).toBeNull();
  });

  it('rejects the internal key itself and other non-credentials', () => {
    expect(verifyRegistryPullCredential(KEY, KEY)).toBeNull();
    expect(verifyRegistryPullCredential('', KEY)).toBeNull();
    expect(verifyRegistryPullCredential(undefined, KEY)).toBeNull();
    expect(verifyRegistryPullCredential('evepull1..', KEY)).toBeNull();
    expect(verifyRegistryPullCredential('evepull2.e30.AAAA', KEY)).toBeNull();
  });

  it('fails closed without a key', () => {
    const credential = mintRegistryPullCredential(CLAIMS, KEY);
    expect(verifyRegistryPullCredential(credential, undefined)).toBeNull();
    expect(verifyRegistryPullCredential(credential, '')).toBeNull();
    expect(() => mintRegistryPullCredential(CLAIMS, undefined)).toThrow(/EVE_INTERNAL_API_KEY/);
  });

  it('requires a project, an environment, a namespace and an epoch', () => {
    expect(() => mintRegistryPullCredential({ ...CLAIMS, projectId: '' }, KEY)).toThrow();
    expect(() => mintRegistryPullCredential({ ...CLAIMS, environmentId: '' }, KEY)).toThrow();
    expect(() => mintRegistryPullCredential({ ...CLAIMS, namespace: '' }, KEY)).toThrow();
    expect(() => mintRegistryPullCredential({ ...CLAIMS, epoch: -1 }, KEY)).toThrow();
    expect(() => mintRegistryPullCredential({ ...CLAIMS, epoch: 1.5 }, KEY)).toThrow();
  });
});

describe('registry push credential', () => {
  it('round-trips the project until it expires', () => {
    const now = 1_700_000_000;
    const credential = mintRegistryPushCredential('proj_abc', KEY, now);
    expect(credential.startsWith('evepush1.')).toBe(true);
    expect(credential).not.toContain(KEY);
    expect(verifyRegistryPushCredential(credential, KEY, now + 60)).toEqual({
      projectId: 'proj_abc',
      expiresAt: now + REGISTRY_PUSH_CREDENTIAL_TTL_SECONDS,
    });
    expect(verifyRegistryPushCredential(credential, KEY, now + REGISTRY_PUSH_CREDENTIAL_TTL_SECONDS)).toBeNull();
  });

  it('is rejected under another key, when tampered with, or without a key', () => {
    const credential = mintRegistryPushCredential('proj_abc', KEY);
    expect(verifyRegistryPushCredential(credential, 'rotated-key')).toBeNull();
    expect(verifyRegistryPushCredential(credential, undefined)).toBeNull();
    const [prefix, , mac] = credential.split('.');
    const forged = Buffer.from(JSON.stringify({ p: 'proj_other', exp: 9_999_999_999 })).toString('base64url');
    expect(verifyRegistryPushCredential(`${prefix}.${forged}.${mac}`, KEY)).toBeNull();
  });

  it('cannot be confused with a pull credential, either way round', () => {
    const push = mintRegistryPushCredential('proj_abc', KEY);
    const pull = mintRegistryPullCredential(CLAIMS, KEY);
    expect(verifyRegistryPullCredential(push, KEY)).toBeNull();
    expect(verifyRegistryPushCredential(pull, KEY)).toBeNull();
    // Same payload, other prefix: the MACs are under different keys.
    const [, payload, mac] = pull.split('.');
    expect(verifyRegistryPushCredential(`evepush1.${payload}.${mac}`, KEY)).toBeNull();
  });
});

describe('the registry credential key', () => {
  it('signs with EVE_REGISTRY_CREDENTIAL_KEY when set, under a version that names the key without revealing it', () => {
    const signer = registryCredentialKey({ EVE_REGISTRY_CREDENTIAL_KEY: 'credential-key', EVE_INTERNAL_API_KEY: KEY });
    expect(signer).toEqual({ key: 'credential-key', version: registryKeyVersion('credential-key') });
    expect(signer!.version).not.toContain('credential-key');
    expect(signer!.version).not.toBe(registryKeyVersion('other-key'));
    expect(signer!.version).not.toBe(REGISTRY_INTERNAL_KEY_VERSION);
    expect(registryKeyVersion('credential-key')).toBe(registryKeyVersion('credential-key'));
  });

  it('falls back to the internal key, under the internal version, until the credential key is set', () => {
    expect(registryCredentialKey({ EVE_INTERNAL_API_KEY: KEY })).toEqual({ key: KEY, version: REGISTRY_INTERNAL_KEY_VERSION });
    expect(registryCredentialKey({})).toBeNull();
  });

  it('a credential signed with one key does not verify under the other', () => {
    const pull = mintRegistryPullCredential(CLAIMS, 'credential-key');
    expect(verifyRegistryPullCredential(pull, 'credential-key')).toEqual(CLAIMS);
    expect(verifyRegistryPullCredential(pull, KEY)).toBeNull();
  });
});
