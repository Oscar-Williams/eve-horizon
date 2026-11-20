import { internalApiFetch, REGISTRY_INTERNAL_KEY_VERSION } from '@eve/shared';

/**
 * The registry key version the API verifies credentials with
 * (`GET /internal/registry/key-version`): its credential key's, `internal`
 * while it signs with the legacy internal key, or null with neither. An API
 * without the route (a release before 0.1.327) verifies with the internal
 * key only.
 */
export async function fetchApiRegistryKeyVersion(): Promise<string | null> {
  const response = await internalApiFetch('/internal/registry/key-version');
  if (response.status === 404) return REGISTRY_INTERNAL_KEY_VERSION;
  if (!response.ok) {
    throw new Error(`The API did not give its registry key version (${response.status})`);
  }
  return ((await response.json()) as { key_version: string | null }).key_version;
}

/**
 * Why the worker must not write pull secrets signed with `workerVersion`:
 * the API verifies with another key (`apiVersion`), so kubelet's next pull
 * would be refused. Null when they agree.
 */
export function registryKeyMismatch(workerVersion: string, apiVersion: string | null | undefined): string | null {
  if (apiVersion === workerVersion) return null;
  return (
    `The worker signs registry credentials with registry key version ${workerVersion}, but the API verifies with ` +
    `${apiVersion ? `registry key version ${apiVersion}` : 'no registry key version it named'}. Set the same ` +
    'EVE_REGISTRY_CREDENTIAL_KEY on the API and the worker (or leave it empty on both), restart them, and try again'
  );
}
