import { createHash } from 'node:crypto';
import type * as k8s from '@kubernetes/client-node';
import { appendK8sSuffix } from '@eve/shared';

/**
 * Values that are credentials (resolved `${secret.*}` and `${managed.*}`
 * references, the service token, app-link tokens) reach a workload through
 * an Opaque Secret Eve writes for it, referenced with `secretKeyRef`, never
 * inline in the Deployment or Job spec.
 */

/** Pod template annotation: a SHA-256 of the Secret's data, so a change rolls the pods. */
export const SECRETS_HASH_ANNOTATION = 'eve.secrets-sha256';
/** Label on a service's Secret; the deployer prunes these. */
export const SERVICE_SECRETS_LABEL = 'eve.service_secrets';
/** Label on a service job's Secret, removed when its run ends. */
export const JOB_SECRETS_LABEL = 'eve.job_secrets';
/** Annotation naming the Deployment a service Secret belongs to. */
export const SECRET_DEPLOYMENT_ANNOTATION = 'eve.deployment';

const CREDENTIAL_REFERENCE = /\$\{(?:secret|managed)\.[^}]+\}/;

/** Whether a manifest env value takes a secret or managed-resource value. */
export function holdsCredentialReference(raw: string): boolean {
  return CREDENTIAL_REFERENCE.test(raw);
}

const SECRET_SUFFIX = 'eve-secrets';

/**
 * `<base>-eve-secrets`. A base too long for the 63-character limit is cut and
 * marked with a hash of the whole base, so two long names never share a Secret.
 */
export function workloadSecretName(base: string): string {
  const name = `${base}-${SECRET_SUFFIX}`;
  if (name.length <= 63) return name;
  const digest = createHash('sha256').update(base).digest('hex').slice(0, 8);
  const room = 63 - SECRET_SUFFIX.length - 1 - digest.length - 1;
  return appendK8sSuffix(`${base.slice(0, room).replace(/-+$/, '')}-${digest}`, SECRET_SUFFIX, 'secret');
}

/**
 * Move the named entries' values into Secret data and reference them with
 * `secretKeyRef` (an env var name is always a valid Secret key). Entries that
 * already read from elsewhere are left as they are.
 */
export function sealEnvEntries(
  entries: k8s.V1EnvVar[],
  credentialNames: ReadonlySet<string>,
  secretName: string,
): { env: k8s.V1EnvVar[]; data: Record<string, string> } {
  const data: Record<string, string> = {};
  const env = entries.map((entry) => {
    if (!credentialNames.has(entry.name) || entry.valueFrom || entry.value === undefined) return entry;
    data[entry.name] = entry.value;
    return { name: entry.name, valueFrom: { secretKeyRef: { name: secretName, key: entry.name } } };
  });
  return { env, data };
}

/** SHA-256 over the whole set of keys and values (not of any one value). */
export function secretsHash(data: Record<string, string>): string {
  const canonical = JSON.stringify(Object.keys(data).sort().map((key) => [key, data[key]]));
  return createHash('sha256').update(canonical).digest('hex');
}

export function buildWorkloadSecret(params: {
  name: string;
  labels: Record<string, string>;
  annotations?: Record<string, string>;
  data: Record<string, string>;
}): Record<string, unknown> {
  return {
    apiVersion: 'v1',
    kind: 'Secret',
    type: 'Opaque',
    metadata: {
      name: params.name,
      labels: params.labels,
      ...(params.annotations ? { annotations: params.annotations } : {}),
    },
    data: Object.fromEntries(
      Object.entries(params.data).map(([key, value]) => [key, Buffer.from(value, 'utf8').toString('base64')]),
    ),
  };
}
