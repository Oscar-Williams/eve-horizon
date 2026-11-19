import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAllDocuments } from 'yaml';

/**
 * Platform secrets in k8s/base: no workload takes all of `eve-app` through
 * `envFrom`. Each takes the keys it reads by `secretKeyRef`, so the gateway
 * holds no database URL and no core key, and the registry credential key
 * reaches the API and the worker only. The new keys are optional, so a
 * cluster whose Secret lacks them still starts on the legacy key.
 */
type SecretKeyRef = { name: string; key: string; optional?: boolean };
type EnvVar = { name: string; value?: string; valueFrom?: { secretKeyRef?: SecretKeyRef; configMapKeyRef?: unknown } };
type Container = { name: string; env?: EnvVar[]; envFrom?: Array<{ secretRef?: { name: string }; configMapRef?: { name: string } }> };
type Manifest = { kind: string; metadata: { name: string }; stringData?: Record<string, string>; spec?: any };

const baseDir = join(__dirname, '..', '..', '..', '..', 'k8s', 'base');
const manifests: Manifest[] = readdirSync(baseDir)
  .filter((file) => file.endsWith('.yaml'))
  .flatMap((file) =>
    parseAllDocuments(readFileSync(join(baseDir, file), 'utf8'))
      .map((doc) => doc.toJSON() as Manifest | null)
      .filter((doc): doc is Manifest => doc !== null),
  );
const workloads = manifests.filter((m) => ['Deployment', 'StatefulSet', 'Job'].includes(m.kind));

function containersOf(workload: Manifest): Container[] {
  const spec = workload.spec?.template?.spec ?? {};
  return [...(spec.containers ?? []), ...(spec.initContainers ?? [])];
}

function envOf(name: string): Map<string, EnvVar> {
  const workload = workloads.find((w) => w.metadata.name === name);
  if (!workload) throw new Error(`k8s/base has no workload ${name}`);
  return new Map(containersOf(workload)[0].env?.map((e) => [e.name, e]) ?? []);
}

/** Workloads whose main container takes this eve-app key. */
function holdersOf(key: string): string[] {
  return workloads
    .filter((w) => containersOf(w)[0]?.env?.some((e) => e.valueFrom?.secretKeyRef?.name === 'eve-app' && e.valueFrom.secretKeyRef.key === key))
    .map((w) => w.metadata.name)
    .sort();
}

const NEW_KEYS = [
  'EVE_INTERNAL_CORE_KEY',
  'EVE_INTERNAL_GATEWAY_KEY',
  'EVE_INTERNAL_SSO_KEY',
  'EVE_INTERNAL_CALLER_HASHES',
  'EVE_REGISTRY_CREDENTIAL_KEY',
];

describe('k8s/base platform secrets', () => {
  it('no workload takes all of eve-app through envFrom', () => {
    const offenders = workloads.filter((w) =>
      containersOf(w).some((c) => c.envFrom?.some((source) => source.secretRef?.name === 'eve-app')));
    expect(offenders.map((w) => w.metadata.name)).toEqual([]);
  });

  it('the eve-app Secret declares the new keys', () => {
    const secret = manifests.find((m) => m.kind === 'Secret' && m.metadata.name === 'eve-app');
    expect(Object.keys(secret?.stringData ?? {})).toEqual(expect.arrayContaining(NEW_KEYS));
  });

  it('the core key reaches the API, worker, orchestrator and agent runtime only', () => {
    expect(holdersOf('EVE_INTERNAL_CORE_KEY')).toEqual(['eve-agent-runtime', 'eve-api', 'eve-orchestrator', 'eve-worker']);
  });

  it('the gateway and the SSO each take their own key, and the hashes of the others', () => {
    expect(holdersOf('EVE_INTERNAL_GATEWAY_KEY')).toEqual(['eve-gateway']);
    expect(holdersOf('EVE_INTERNAL_SSO_KEY')).toEqual(['eve-sso']);
    expect(holdersOf('EVE_INTERNAL_CALLER_HASHES')).toEqual(expect.arrayContaining(['eve-api', 'eve-gateway']));
  });

  it('the registry credential key reaches the API and the worker only', () => {
    expect(holdersOf('EVE_REGISTRY_CREDENTIAL_KEY')).toEqual(['eve-api', 'eve-worker']);
  });

  it('the gateway holds no database URL, master key or core key', () => {
    const gateway = envOf('eve-gateway');
    for (const key of ['DATABASE_URL', 'EVE_SECRETS_MASTER_KEY', 'EVE_INTERNAL_CORE_KEY', 'EVE_REGISTRY_CREDENTIAL_KEY']) {
      expect(gateway.has(key), key).toBe(false);
    }
  });

  it('the SSO holds no database URL, master key or core key', () => {
    const sso = envOf('eve-sso');
    for (const key of ['DATABASE_URL', 'EVE_SECRETS_MASTER_KEY', 'EVE_INTERNAL_CORE_KEY', 'EVE_BOOTSTRAP_TOKEN']) {
      expect(sso.has(key), key).toBe(false);
    }
  });

  it('every eve-app key a workload takes is declared in the Secret, and the internal keys are optional', () => {
    const declared = new Set(Object.keys(manifests.find((m) => m.kind === 'Secret' && m.metadata.name === 'eve-app')?.stringData ?? {}));
    const refs = workloads.flatMap((w) => containersOf(w).flatMap((c) => c.env ?? []))
      .map((e) => e.valueFrom?.secretKeyRef)
      .filter((ref): ref is SecretKeyRef => ref?.name === 'eve-app');
    expect(refs.length).toBeGreaterThan(0);
    expect(refs.filter((ref) => !declared.has(ref.key)).map((ref) => ref.key)).toEqual([]);
    const internal = refs.filter((ref) => [...NEW_KEYS, 'EVE_INTERNAL_API_KEY'].includes(ref.key));
    expect(internal.filter((ref) => ref.optional !== true).map((ref) => ref.key)).toEqual([]);
  });
});
