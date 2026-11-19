import yaml from 'yaml';
import { REGISTRY_PULL_USERNAME } from '@eve/shared';

/** The image pull secret Eve writes into each app namespace that uses the Eve registry. */
export const EVE_REGISTRY_SECRET_NAME = 'eve-registry';

/** The `eve-registry` Secret, as YAML, carrying an environment's pull credential for the registry host. */
export function evePullSecretManifest(namespace: string, registryHost: string, credential: string): string {
  const username = REGISTRY_PULL_USERNAME;
  const auth = Buffer.from(`${username}:${credential}`).toString('base64');
  const dockerConfig = { auths: { [registryHost]: { username, password: credential, auth } } };
  return yaml.stringify({
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: { name: EVE_REGISTRY_SECRET_NAME, namespace },
    type: 'kubernetes.io/dockerconfigjson',
    data: { '.dockerconfigjson': Buffer.from(JSON.stringify(dockerConfig)).toString('base64') },
  });
}

/**
 * The registry host and pull credential in an `eve-registry` Secret's data,
 * or null when it holds no Eve pull credential (absent, or a bring-your-own
 * registry's credentials).
 */
export function evePullCredentialIn(
  data: Record<string, string> | null | undefined,
): { host: string; credential: string } | null {
  const encoded = data?.['.dockerconfigjson'];
  if (!encoded) return null;
  try {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8')) as {
      auths?: Record<string, { username?: string; password?: string }>;
    };
    for (const [host, entry] of Object.entries(parsed.auths ?? {})) {
      if (entry?.username === REGISTRY_PULL_USERNAME && typeof entry.password === 'string') {
        return { host, credential: entry.password };
      }
    }
  } catch {
    return null;
  }
  return null;
}
