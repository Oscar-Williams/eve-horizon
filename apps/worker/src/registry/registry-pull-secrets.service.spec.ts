import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import yaml from 'yaml';
import { mintRegistryPullCredential, registryKeyVersion, verifyRegistryPullCredential } from '@eve/shared';
import { RegistryPullSecretsService } from './registry-pull-secrets.service.js';

/**
 * Reconcile re-signs each environment's `eve-registry` pull secret with the
 * registry credential key, with no restart, and records the key version and
 * epoch on the environment. A secret already signed with the current key at
 * the current epoch is only recorded; a bring-your-own registry secret is
 * never touched.
 */
const KEY = 'registry-credential-key';
const INTERNAL = 'internal-key';
const HOST = 'registry.eve.example.com';

type Candidate = {
  id: string;
  project_id: string;
  name: string;
  namespace: string | null;
  registry_pull_epoch: number;
  org_slug: string;
  project_slug: string;
};

function dockerConfigSecret(username: string, password: string) {
  const auth = Buffer.from(`${username}:${password}`).toString('base64');
  return { '.dockerconfigjson': Buffer.from(JSON.stringify({ auths: { [HOST]: { username, password, auth } } })).toString('base64') };
}

describe('RegistryPullSecretsService.resign', () => {
  let epochs: Map<string, number>;
  let secrets: Map<string, Record<string, string> | null>;
  const applyManifest = vi.fn();
  const recordRegistryKeyVersion = vi.fn();
  let candidates: Candidate[];
  let service: RegistryPullSecretsService;

  const candidate = (id: string, epoch: number, namespace: string | null = null): Candidate => ({
    id, project_id: 'proj_shop', name: id.replace('env_', ''), namespace, registry_pull_epoch: epoch,
    org_slug: 'acme', project_slug: 'shop',
  });

  beforeEach(() => {
    vi.stubEnv('DATABASE_URL', 'postgres://user:pass@localhost:5432/eve_test');
    vi.stubEnv('EVE_INTERNAL_API_KEY', INTERNAL);
    vi.stubEnv('EVE_REGISTRY_CREDENTIAL_KEY', KEY);
    applyManifest.mockReset();
    recordRegistryKeyVersion.mockReset();
    epochs = new Map([['env_old', 3], ['env_current', 7], ['env_byo', 2], ['env_none', 5]]);
    candidates = [candidate('env_old', 3), candidate('env_current', 7, 'shop-current'), candidate('env_byo', 2), candidate('env_none', 5)];
    secrets = new Map<string, Record<string, string> | null>([
      ['eve-acme-shop-old', dockerConfigSecret('eve-pull', mintRegistryPullCredential(
        { projectId: 'proj_shop', environmentId: 'env_old', namespace: 'eve-acme-shop-old', epoch: 3 }, INTERNAL))],
      ['shop-current', dockerConfigSecret('eve-pull', mintRegistryPullCredential(
        { projectId: 'proj_shop', environmentId: 'env_current', namespace: 'shop-current', epoch: 7 }, KEY))],
      ['eve-acme-shop-byo', dockerConfigSecret('robot', 'byo-token')],
      ['eve-acme-shop-none', null],
    ]);
    service = new RegistryPullSecretsService(null as never, { applyManifest } as never);
    Object.assign(service as object, {
      environments: {
        listRegistryKeyCandidates: vi.fn(async () => candidates),
        bumpRegistryPullEpoch: vi.fn(async (id: string) => {
          const next = (epochs.get(id) ?? 0) + 1;
          epochs.set(id, next);
          return next;
        }),
        recordRegistryKeyVersion,
      },
      readSecretData: vi.fn(async (namespace: string) => secrets.get(namespace) ?? null),
    });
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('re-signs a pull secret signed with the internal key, at a new epoch, and records its key version', async () => {
    const report = await service.resign(registryKeyVersion(KEY));

    expect(applyManifest).toHaveBeenCalledTimes(1);
    const [namespace, manifest] = applyManifest.mock.calls[0] as [string, string];
    expect(namespace).toBe('eve-acme-shop-old');
    const secret = yaml.parse(manifest) as { metadata: { name: string }; type: string; data: Record<string, string> };
    expect(secret.metadata.name).toBe('eve-registry');
    expect(secret.type).toBe('kubernetes.io/dockerconfigjson');
    const entry = JSON.parse(Buffer.from(secret.data['.dockerconfigjson'], 'base64').toString('utf8')).auths[HOST];
    expect(entry.username).toBe('eve-pull');
    expect(verifyRegistryPullCredential(entry.password, KEY)).toEqual({
      projectId: 'proj_shop', environmentId: 'env_old', namespace: 'eve-acme-shop-old', epoch: 4,
    });
    expect(recordRegistryKeyVersion).toHaveBeenCalledWith('env_old', registryKeyVersion(KEY), 4);
    expect(report).toMatchObject({ key_version: registryKeyVersion(KEY), resigned: 1 });
  });

  it('only records a secret already signed with the current key at the current epoch', async () => {
    const report = await service.resign(registryKeyVersion(KEY));
    expect(applyManifest.mock.calls.map(([ns]) => ns)).not.toContain('shop-current');
    expect(recordRegistryKeyVersion).toHaveBeenCalledWith('env_current', registryKeyVersion(KEY), 7);
    expect(report.already_current).toBe(1);
  });

  it('leaves a bring-your-own secret and a missing one alone, and records that nothing needs re-signing', async () => {
    const report = await service.resign(registryKeyVersion(KEY));
    expect(applyManifest.mock.calls.map(([ns]) => ns)).toEqual(['eve-acme-shop-old']);
    expect(recordRegistryKeyVersion).toHaveBeenCalledWith('env_byo', registryKeyVersion(KEY), 2);
    expect(recordRegistryKeyVersion).toHaveBeenCalledWith('env_none', registryKeyVersion(KEY), 5);
    expect(report.without_pull_secret).toBe(2);
  });

  it('reports an environment it could not re-sign, records nothing for it, and carries on', async () => {
    candidates = [candidate('env_old', 3), candidate('env_none', 5)];
    applyManifest.mockRejectedValueOnce(new Error('namespace is terminating'));
    const report = await service.resign(registryKeyVersion(KEY));
    expect(report.failed).toEqual([{ environment_id: 'env_old', error: 'namespace is terminating' }]);
    expect(recordRegistryKeyVersion).not.toHaveBeenCalledWith('env_old', expect.anything(), expect.anything());
    expect(recordRegistryKeyVersion).toHaveBeenCalledWith('env_none', registryKeyVersion(KEY), 5);
  });

  it('asks for the stale environments only', async () => {
    await service.resign(registryKeyVersion(KEY));
    expect((service as any).environments.listRegistryKeyCandidates).toHaveBeenCalledWith(registryKeyVersion(KEY));
  });

  it('moves pull secrets back to the internal key when no credential key is set (the way back for a rollback)', async () => {
    vi.stubEnv('EVE_REGISTRY_CREDENTIAL_KEY', '');
    candidates = [candidate('env_current', 7, 'shop-current')];
    const report = await service.resign('internal');
    expect((service as any).environments.listRegistryKeyCandidates).toHaveBeenCalledWith('internal');
    const [, manifest] = applyManifest.mock.calls[0] as [string, string];
    const entry = JSON.parse(Buffer.from((yaml.parse(manifest) as { data: Record<string, string> }).data['.dockerconfigjson'], 'base64')
      .toString('utf8')).auths[HOST];
    expect(verifyRegistryPullCredential(entry.password, INTERNAL)).toMatchObject({ environmentId: 'env_current', epoch: 8 });
    expect(recordRegistryKeyVersion).toHaveBeenCalledWith('env_current', 'internal', 8);
    expect(report).toMatchObject({ key_version: 'internal', resigned: 1 });
  });

  it('refuses to run with no registry key at all', async () => {
    vi.stubEnv('EVE_REGISTRY_CREDENTIAL_KEY', '');
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    await expect(service.resign(null)).rejects.toThrow(/EVE_REGISTRY_CREDENTIAL_KEY/);
    expect(applyManifest).not.toHaveBeenCalled();
  });

  it('refuses to re-sign with a key the API does not verify with, and touches no environment', async () => {
    // The API holds another credential key, or still only the internal key.
    await expect(service.resign(registryKeyVersion('another-credential-key'))).rejects.toThrow(/registry key version/);
    await expect(service.resign('internal')).rejects.toThrow(/registry key version/);
    // An API that did not say which key it holds.
    await expect(service.resign(undefined)).rejects.toThrow(/registry key version/);
    expect((service as any).environments.listRegistryKeyCandidates).not.toHaveBeenCalled();
    expect(applyManifest).not.toHaveBeenCalled();
    expect(recordRegistryKeyVersion).not.toHaveBeenCalled();
  });

  it('refuses the internal-key way back while the API still holds a credential key', async () => {
    vi.stubEnv('EVE_REGISTRY_CREDENTIAL_KEY', '');
    await expect(service.resign(registryKeyVersion(KEY))).rejects.toThrow(/registry key version/);
    expect(applyManifest).not.toHaveBeenCalled();
  });
});
