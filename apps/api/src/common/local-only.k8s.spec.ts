import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse, parseAllDocuments } from 'yaml';

/**
 * Local-only pieces stay out of k8s/base, which installs build on.
 *
 * - RT-22: the mailpit and MinIO ingresses, and the MinIO console, are the
 *   local stack's; k8s/overlays/local brings them back.
 * - The base Postgres password: base names none. `bin/eh` generates one for
 *   a new local install, before Postgres first starts (POSTGRES_PASSWORD is
 *   read only when the data directory is created), and keeps the one an
 *   existing install has. DATABASE_URL is a Secret key, not ConfigMap data.
 */

type EnvVar = { name: string; value?: string; valueFrom?: { secretKeyRef?: { name: string; key: string }; configMapKeyRef?: { key: string } } };
type Container = { name: string; args?: string[]; env?: EnvVar[]; ports?: Array<{ containerPort: number }> };
type Manifest = { kind: string; metadata: { name: string }; data?: Record<string, string>; stringData?: Record<string, string>; spec?: any };

const root = join(__dirname, '..', '..', '..', '..');
const baseDir = join(root, 'k8s', 'base');
const localDir = join(root, 'k8s', 'overlays', 'local');

function documents(file: string): Manifest[] {
  return parseAllDocuments(readFileSync(file, 'utf8'))
    .map((doc) => doc.toJSON() as Manifest | null)
    .filter((doc): doc is Manifest => doc !== null);
}

const baseKustomization = parse(readFileSync(join(baseDir, 'kustomization.yaml'), 'utf8')) as { resources: string[] };
const localKustomization = parse(readFileSync(join(localDir, 'kustomization.yaml'), 'utf8')) as {
  resources: string[];
  patchesStrategicMerge?: string[];
};
// What base installs: the files its kustomization lists, and the migrate Job
// `bin/eh` applies on its own.
const baseFiles = [...baseKustomization.resources.filter((resource) => resource.endsWith('.yaml')), 'db-migrate-job.yaml'];
const base = baseFiles.flatMap((resource) => documents(join(baseDir, resource)));
const find = (kind: string, name: string) => base.find((m) => m.kind === kind && m.metadata.name === name);
const containersOf = (workload: Manifest): Container[] => workload.spec?.template?.spec?.containers ?? [];

describe('RT-22: local-only services stay out of k8s/base', () => {
  it('base declares no ingress for mailpit or MinIO', () => {
    const backends = base.filter((m) => m.kind === 'Ingress')
      .flatMap((m) => (m.spec?.rules ?? []).flatMap((rule: any) => rule.http?.paths ?? []))
      .map((path: any) => path.backend?.service?.name);
    expect(backends).not.toContain('mailpit');
    expect(backends).not.toContain('eve-minio');
    expect(readdirSync(baseDir)).not.toEqual(expect.arrayContaining(['mailpit-ingress.yaml']));
    expect(readdirSync(baseDir)).not.toEqual(expect.arrayContaining(['minio-ingress.yaml']));
  });

  it('base runs MinIO with its console off and unexposed', () => {
    const minio = containersOf(find('StatefulSet', 'eve-minio')!)[0];
    expect(minio.args ?? []).not.toContain('--console-address');
    expect(minio.env?.find((e) => e.name === 'MINIO_BROWSER')?.value).toBe('off');
    expect((minio.ports ?? []).map((p) => p.containerPort)).toEqual([9000]);
    expect(find('Service', 'eve-minio')?.spec.ports.map((p: { port: number }) => p.port)).toEqual([9000]);
  });

  it('the local overlay brings the ingresses and the console back', () => {
    expect(localKustomization.resources).toEqual(expect.arrayContaining(['mailpit-ingress.yaml', 'minio-ingress.yaml']));
    expect(localKustomization.patchesStrategicMerge).toContain('minio-console.patch.yaml');
    for (const file of ['mailpit-ingress.yaml', 'minio-ingress.yaml', 'minio-console.patch.yaml']) {
      expect(existsSync(join(localDir, file)), file).toBe(true);
    }
    const console = containersOf(documents(join(localDir, 'minio-console.patch.yaml'))[0])[0];
    expect(console.args).toEqual(expect.arrayContaining(['--console-address', ':9001']));
    expect(console.env?.find((e) => e.name === 'MINIO_BROWSER')?.value).toBe('on');
  });
});

describe('the base Postgres password', () => {
  it('base names no Postgres password and puts no database URL in a ConfigMap', () => {
    expect(find('Secret', 'eve-postgres')).toBeUndefined();
    expect(find('ConfigMap', 'eve-cluster-config')?.data ?? {}).not.toHaveProperty('DATABASE_URL');
    const text = baseFiles.map((resource) => readFileSync(join(baseDir, resource), 'utf8')).join('\n');
    expect(text).not.toMatch(/postgres:\/\/eve:eve@/);
    expect(text).not.toMatch(/POSTGRES_PASSWORD:\s*eve\b/);
  });

  it('DATABASE_URL reaches the API, worker, orchestrator, agent runtime and migrate job from eve-app', () => {
    const holders = base
      .filter((m) => ['Deployment', 'StatefulSet', 'Job'].includes(m.kind))
      .filter((m) => containersOf(m).some((c) => c.env?.some((e) => e.name === 'DATABASE_URL'
        && e.valueFrom?.secretKeyRef?.name === 'eve-app' && e.valueFrom.secretKeyRef.key === 'DATABASE_URL')))
      .map((m) => m.metadata.name)
      .sort();
    expect(holders).toEqual(['eve-agent-runtime', 'eve-api', 'eve-db-migrate', 'eve-orchestrator', 'eve-worker']);
    expect(Object.keys(find('Secret', 'eve-app')?.stringData ?? {})).toContain('DATABASE_URL');
  });

  it('bin/eh makes the Postgres Secret before Postgres first starts, keeping one that exists', () => {
    const script = readFileSync(join(root, 'bin', 'eh-commands', 'k8s.sh'), 'utf8');
    const ensure = /ensure_postgres_secret\(\) \{([\s\S]*?)\n\}/.exec(script)?.[1] ?? '';
    expect(ensure).toMatch(/get secret eve-postgres/);
    expect(ensure).toMatch(/openssl rand/);
    for (const flow of [/run_deploy\(\) \{([\s\S]*?)\n\}/, /\n {2}start\)([\s\S]*?)\n {2}deploy\)/]) {
      const body = flow.exec(script)?.[1] ?? '';
      const ensured = body.indexOf('ensure_postgres_secret');
      expect(ensured).toBeGreaterThan(-1);
      expect(ensured).toBeLessThan(body.indexOf('apply -k "$LOCAL_OVERLAY"'));
    }
    expect(script).toMatch(/apply_database_url/);
  });
});
