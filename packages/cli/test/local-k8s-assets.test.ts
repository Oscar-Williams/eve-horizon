import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAllDocuments } from 'yaml';

function readFixture(path: string): string {
  return readFileSync(new URL(path, import.meta.url), 'utf8');
}

describe('local k8s assets', () => {
  it('mirrors the agent-runtime base manifest', () => {
    expect(readFixture('../../../k8s/base/agent-runtime-deployment.yaml')).toBe(
      readFixture('../assets/local-k8s/base/agent-runtime-deployment.yaml'),
    );
  });

  it('mirrors the agent-runtime local overlay patch', () => {
    expect(readFixture('../../../k8s/overlays/local/agent-runtime-org-id.patch.yaml')).toBe(
      readFixture('../assets/local-k8s/overlays/local/agent-runtime-org-id.patch.yaml'),
    );
  });
});

/**
 * The platform Secret in the stack `eve local up` deploys follows k8s/base:
 * no workload takes all of `eve-app` through `envFrom`, each takes the keys
 * it reads by `secretKeyRef`, and every key a workload reads exists, in the
 * asset Secret or because `eve local up` writes it. A service that opens the
 * database gets `DATABASE_URL` from somewhere the stack defines.
 */
type SecretKeyRef = { name: string; key: string; optional?: boolean };
type ConfigMapKeyRef = { name: string; key: string };
type EnvVar = { name: string; value?: string; valueFrom?: { secretKeyRef?: SecretKeyRef; configMapKeyRef?: ConfigMapKeyRef } };
type Container = { name: string; env?: EnvVar[]; envFrom?: Array<{ secretRef?: { name: string }; configMapRef?: { name: string } }> };
type Manifest = { kind: string; metadata: { name: string }; stringData?: Record<string, string>; data?: Record<string, string>; spec?: any };

const baseDir = join(__dirname, '..', 'assets', 'local-k8s', 'base');
const manifests: Manifest[] = readdirSync(baseDir)
  .filter((file) => file.endsWith('.yaml'))
  .flatMap((file) =>
    parseAllDocuments(readFileSync(join(baseDir, file), 'utf8'))
      .map((doc) => doc.toJSON() as Manifest | null)
      .filter((doc): doc is Manifest => doc !== null),
  );
const workloads = manifests.filter((m) => ['Deployment', 'StatefulSet', 'Job'].includes(m.kind));
const appSecret = manifests.find((m) => m.kind === 'Secret' && m.metadata.name === 'eve-app');
const clusterConfig = manifests.find((m) => m.kind === 'ConfigMap' && m.metadata.name === 'eve-cluster-config');

function containersOf(workload: Manifest): Container[] {
  return workload.spec?.template?.spec?.containers ?? [];
}

function mainContainer(name: string): Container {
  const found = workloads.find((w) => w.metadata.name === name);
  if (!found) throw new Error(`the local stack has no workload ${name}`);
  return containersOf(found)[0];
}

const takesAllOfEveApp = (c: Container) => c.envFrom?.some((source) => source.secretRef?.name === 'eve-app') ?? false;

/** Workloads whose main container holds this eve-app key, by ref or through envFrom. */
function holdersOf(key: string): string[] {
  return workloads
    .filter((w) => {
      const c = containersOf(w)[0];
      return takesAllOfEveApp(c)
        || (c.env?.some((e) => e.valueFrom?.secretKeyRef?.name === 'eve-app' && e.valueFrom.secretKeyRef.key === key) ?? false);
    })
    .map((w) => w.metadata.name)
    .sort();
}

/** The eve-app values `eve local up` writes, given what the Secret already holds. */
async function writtenByLocalUp(existing: Record<string, string> = {}): Promise<Record<string, string>> {
  const { localPlatformSecrets } = await import('../src/commands/local');
  return localPlatformSecrets((key: string) => existing[key] ?? '', {});
}

describe('local k8s platform secrets', () => {
  it('no workload takes all of eve-app through envFrom', () => {
    const offenders = workloads.filter((w) => containersOf(w).some(takesAllOfEveApp));
    expect(offenders.map((w) => w.metadata.name)).toEqual([]);
  });

  it('every eve-app key a workload reads is in the Secret or written by eve local up, unless a local stack may lack it', async () => {
    // Optional settings a local stack runs without, as an install may.
    const mayLack = ['EVE_REGISTRY_SIGNING_KEY', 'EVE_ORG_FS_LINK_TOKEN_SECRET', 'EVE_GITHUB_TOKEN'];
    const available = new Set([...Object.keys(appSecret?.stringData ?? {}), ...Object.keys(await writtenByLocalUp()), ...mayLack]);
    const missing = workloads.flatMap((w) =>
      containersOf(w).flatMap((c) => c.env ?? [])
        .map((e) => e.valueFrom?.secretKeyRef)
        .filter((ref): ref is SecretKeyRef => ref?.name === 'eve-app' && !available.has(ref.key))
        .map((ref) => `${w.metadata.name}:${ref.key}`));
    expect(missing).toEqual([]);
  });

  it('every service that opens the database gets a DATABASE_URL the stack defines', async () => {
    const written = await writtenByLocalUp();
    for (const name of ['eve-api', 'eve-worker', 'eve-orchestrator', 'eve-agent-runtime', 'eve-db-migrate']) {
      const env = mainContainer(name).env?.find((e) => e.name === 'DATABASE_URL');
      const configRef = env?.valueFrom?.configMapKeyRef;
      const secretRef = env?.valueFrom?.secretKeyRef;
      const defined = Boolean(env?.value)
        || (configRef?.name === 'eve-cluster-config' && Boolean(clusterConfig?.data?.[configRef.key]))
        || (secretRef?.name === 'eve-app' && Boolean(written[secretRef.key] || appSecret?.stringData?.[secretRef.key]));
      expect(defined, name).toBe(true);
    }
  });

  it('the core key reaches the API, worker, orchestrator and agent runtime only', () => {
    expect(holdersOf('EVE_INTERNAL_CORE_KEY')).toEqual(['eve-agent-runtime', 'eve-api', 'eve-orchestrator', 'eve-worker']);
  });

  it('the gateway and the SSO take their own keys, and the deliver key reaches the API only', () => {
    expect(holdersOf('EVE_INTERNAL_GATEWAY_KEY')).toEqual(['eve-gateway']);
    expect(holdersOf('EVE_INTERNAL_SSO_KEY')).toEqual(['eve-sso']);
    expect(holdersOf('EVE_INTERNAL_DELIVER_KEY')).toEqual(['eve-api']);
    expect(holdersOf('EVE_INTERNAL_CALLER_HASHES')).toEqual(['eve-api', 'eve-gateway']);
  });

  it('the registry credential key reaches the API and the worker only, as a required ref the Secret declares', () => {
    expect(holdersOf('EVE_REGISTRY_CREDENTIAL_KEY')).toEqual(['eve-api', 'eve-worker']);
    for (const name of ['eve-api', 'eve-worker']) {
      const ref = mainContainer(name).env?.find((e) => e.name === 'EVE_REGISTRY_CREDENTIAL_KEY')?.valueFrom?.secretKeyRef;
      expect(ref?.optional, name).not.toBe(true);
    }
    expect(Object.keys(appSecret?.stringData ?? {})).toContain('EVE_REGISTRY_CREDENTIAL_KEY');
  });

  it('the gateway and the SSO hold no database URL, master key or core key', () => {
    for (const name of ['eve-gateway', 'eve-sso']) {
      const c = mainContainer(name);
      expect(takesAllOfEveApp(c), name).toBe(false);
      const names = new Set(c.env?.map((e) => e.name));
      for (const key of ['DATABASE_URL', 'EVE_SECRETS_MASTER_KEY', 'EVE_INTERNAL_CORE_KEY', 'EVE_REGISTRY_CREDENTIAL_KEY']) {
        expect(names.has(key), `${name}:${key}`).toBe(false);
      }
    }
  });

  it('eve local up writes every internal key, and the hashes of those callees hold only by hash', async () => {
    const written = await writtenByLocalUp();
    const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');
    for (const key of ['EVE_INTERNAL_CORE_KEY', 'EVE_INTERNAL_GATEWAY_KEY', 'EVE_INTERNAL_SSO_KEY', 'EVE_INTERNAL_DELIVER_KEY', 'EVE_REGISTRY_CREDENTIAL_KEY']) {
      expect(written[key], key).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(written.EVE_INTERNAL_CALLER_HASHES.split(',').sort()).toEqual([
      `core:${sha(written.EVE_INTERNAL_CORE_KEY)}`,
      `deliver:${sha(written.EVE_INTERNAL_DELIVER_KEY)}`,
      `gateway:${sha(written.EVE_INTERNAL_GATEWAY_KEY)}`,
      `sso:${sha(written.EVE_INTERNAL_SSO_KEY)}`,
    ]);
  });

  it('eve local up keeps what an earlier run wrote', async () => {
    const written = await writtenByLocalUp({
      EVE_INTERNAL_DELIVER_KEY: 'kept-deliver-key',
      EVE_REGISTRY_CREDENTIAL_KEY: 'kept-registry-key',
      DATABASE_URL: 'postgres://kept@postgres.eve.svc.cluster.local:5432/eve',
    });
    expect(written.EVE_INTERNAL_DELIVER_KEY).toBe('kept-deliver-key');
    expect(written.EVE_REGISTRY_CREDENTIAL_KEY).toBe('kept-registry-key');
    expect(written.DATABASE_URL).toBe('postgres://kept@postgres.eve.svc.cluster.local:5432/eve');
  });
});
