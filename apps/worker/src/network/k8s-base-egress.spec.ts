import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse, parseAllDocuments } from 'yaml';
import { runnerDenyPolicies, runnerIngressPolicies } from '@eve/shared';

/**
 * k8s/base for egress.default_deny: the static runner policies (fail closed:
 * deny every runner pod's egress but DNS and the API's public port, and take
 * connections only from the worker on the submit port), the worker's rights
 * on NetworkPolicies, and the API URL apps and runners are given.
 */
type Manifest = { kind: string; metadata: { name: string; namespace?: string; labels?: Record<string, string> };
  spec?: any; data?: Record<string, string>; rules?: Array<{ apiGroups: string[]; resources: string[]; verbs: string[] }> };

const baseDir = join(__dirname, '..', '..', '..', '..', 'k8s', 'base');
const manifests: Manifest[] = readdirSync(baseDir)
  .filter((file) => file.endsWith('.yaml'))
  .flatMap((file) => parseAllDocuments(readFileSync(join(baseDir, file), 'utf8'))
    .map((doc) => doc.toJSON() as Manifest | null)
    .filter((doc): doc is Manifest => doc !== null));

function find(kind: string, name: string, namespace?: string): Manifest {
  const found = manifests.find((m) => m.kind === kind && m.metadata.name === name
    && (namespace === undefined || m.metadata.namespace === namespace));
  if (!found) throw new Error(`k8s/base has no ${kind} ${namespace ? `${namespace}/` : ''}${name}`);
  return found;
}

describe('k8s/base runner policies', () => {
  const namespaces = { runnerNamespace: 'eve-runners', platformNamespace: 'eve' };

  it('denies every runner pod all egress but DNS and eve-api on 4701, in eve-runners and eve', () => {
    for (const expected of runnerDenyPolicies(namespaces)) {
      const policy = find('NetworkPolicy', 'eve-runner-deny', expected.metadata.namespace);
      expect(policy.spec).toEqual(expected.spec);
    }
  });

  it('lets only the worker reach runner pods, on 4749, in eve-runners and eve', () => {
    for (const expected of runnerIngressPolicies(namespaces)) {
      const policy = find('NetworkPolicy', 'eve-runner-ingress', expected.metadata.namespace);
      expect(policy.spec).toEqual(expected.spec);
    }
    const worker = find('Deployment', 'eve-worker');
    expect(worker.spec.template.metadata.labels['app.kubernetes.io/name']).toBe('eve-worker');
  });

  it('is part of the kustomization', () => {
    const kustomization = parse(readFileSync(join(baseDir, 'kustomization.yaml'), 'utf8')) as { resources: string[] };
    expect(kustomization.resources).toContain('runner-network-policies.yaml');
  });
});

describe('k8s/base worker rights and API URLs', () => {
  it('lets the worker manage NetworkPolicies', () => {
    const role = find('ClusterRole', 'eve-worker');
    const verbs = (role.rules ?? [])
      .filter((r) => r.apiGroups.includes('networking.k8s.io') && r.resources.includes('networkpolicies'))
      .flatMap((r) => r.verbs);
    expect(verbs).toEqual(expect.arrayContaining(['get', 'list', 'create', 'patch', 'update', 'delete']));
  });

  it('lets the worker manage GKE FQDN policies (harmless where the CRD is absent)', () => {
    const role = find('ClusterRole', 'eve-worker');
    const verbs = (role.rules ?? [])
      .filter((r) => r.apiGroups.includes('networking.gke.io') && r.resources.includes('fqdnnetworkpolicies'))
      .flatMap((r) => r.verbs);
    expect(verbs).toEqual(expect.arrayContaining(['get', 'list', 'create', 'update', 'delete']));
  });

  it('gives apps and runners the public API port, and platform services the internal one', () => {
    const config = find('ConfigMap', 'eve-cluster-config').data!;
    expect(config.EVE_API_APP_URL).toBe('http://eve-api.eve.svc.cluster.local:4701');
    expect(new URL(config.EVE_API_URL).port).toBe('4791');
    const api = find('Deployment', 'eve-api');
    const env = api.spec.template.spec.containers[0].env as Array<{ name: string; value?: string }>;
    expect(env.find((e) => e.name === 'EVE_API_INTERNAL_PORT')?.value).toBe('4791');
    expect(env.find((e) => e.name === 'API_PORT')?.value).toBe('4701');
  });
});
