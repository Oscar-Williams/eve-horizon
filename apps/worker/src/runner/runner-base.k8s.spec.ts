import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAllDocuments } from 'yaml';

/**
 * k8s/base for runner pods: they run as `eve-runner`, an account with no
 * token mount and no RBAC, never as the worker's own account; and the worker
 * and agent runtime refuse to start when job processes could read their
 * environment.
 */
type Manifest = { kind: string; metadata: { name: string; namespace?: string }; automountServiceAccountToken?: boolean;
  subjects?: Array<{ kind: string; name: string }>; spec?: any };

const baseDir = join(__dirname, '..', '..', '..', '..', 'k8s', 'base');
const manifests: Manifest[] = readdirSync(baseDir)
  .filter((file) => file.endsWith('.yaml'))
  .flatMap((file) => parseAllDocuments(readFileSync(join(baseDir, file), 'utf8'))
    .map((doc) => doc.toJSON() as Manifest | null)
    .filter((doc): doc is Manifest => doc !== null));

function envOf(name: string): Record<string, string | undefined> {
  const workload = manifests.find((m) => ['Deployment', 'StatefulSet'].includes(m.kind) && m.metadata.name === name);
  if (!workload) throw new Error(`k8s/base has no workload ${name}`);
  const env = workload.spec.template.spec.containers[0].env as Array<{ name: string; value?: string }>;
  return Object.fromEntries(env.map((e) => [e.name, e.value]));
}

describe('k8s/base runner identity', () => {
  it('defines eve-runner with no token mount and binds it to no role', () => {
    const account = manifests.find((m) => m.kind === 'ServiceAccount' && m.metadata.name === 'eve-runner');
    expect(account).toBeDefined();
    expect(account!.automountServiceAccountToken).toBe(false);
    const bound = manifests
      .filter((m) => m.kind === 'RoleBinding' || m.kind === 'ClusterRoleBinding')
      .flatMap((m) => m.subjects ?? [])
      .filter((s) => s.kind === 'ServiceAccount' && s.name === 'eve-runner');
    expect(bound).toEqual([]);
  });

  it('runs runner pods as eve-runner', () => {
    expect(envOf('eve-worker').EVE_RUNNER_SERVICE_ACCOUNT).toBe('eve-runner');
  });

  it('makes the worker and agent runtime refuse to start with a readable environment', () => {
    expect(envOf('eve-worker').EVE_REQUIRE_ENVIRON_PROTECTION).toBe('true');
    expect(envOf('eve-agent-runtime').EVE_REQUIRE_ENVIRON_PROTECTION).toBe('true');
  });
});

describe('k8s/base runner namespace and worker rights', () => {
  const ns = process.env.EVE_RUNNER_NAMESPACE_FOR_TEST ?? 'eve-runners';

  it('has a runner namespace that enforces Pod Security restricted', () => {
    const namespace = manifests.find((m) => m.kind === 'Namespace' && m.metadata.name === ns) as Manifest & { metadata: { labels?: Record<string, string> } };
    expect(namespace?.metadata.labels).toMatchObject({
      'pod-security.kubernetes.io/enforce': 'restricted',
      'pod-security.kubernetes.io/warn': 'restricted',
      'pod-security.kubernetes.io/audit': 'restricted',
    });
    const account = manifests.find((m) => m.kind === 'ServiceAccount' && m.metadata.name === 'eve-runner' && m.metadata.namespace === ns);
    expect(account?.automountServiceAccountToken).toBe(false);
    expect(envOf('eve-worker').EVE_RUNNER_NAMESPACE).toBe(ns);
  });

  it('lets the worker claim sandboxes and manage fallback pods there, and nothing on sandboxes', () => {
    const role = manifests.find((m) => m.kind === 'Role' && m.metadata.namespace === ns && m.metadata.name === 'eve-worker-runners') as Manifest & {
      rules: Array<{ apiGroups: string[]; resources: string[]; verbs: string[] }>;
    };
    expect(role).toBeDefined();
    const verbs = (group: string, resource: string) => role.rules
      .filter((r) => r.apiGroups.includes(group) && r.resources.includes(resource))
      .flatMap((r) => r.verbs);
    expect(verbs('extensions.agents.x-k8s.io', 'sandboxclaims')).toEqual(expect.arrayContaining(['create', 'get', 'delete', 'watch']));
    expect(verbs('extensions.agents.x-k8s.io', 'sandboxtemplates')).toEqual(expect.arrayContaining(['get', 'list']));
    expect(verbs('extensions.agents.x-k8s.io', 'sandboxwarmpools')).toEqual(expect.arrayContaining(['get', 'list']));
    expect(verbs('agents.x-k8s.io', 'sandboxes')).toEqual([]);
    expect(verbs('', 'pods')).toEqual(expect.arrayContaining(['create', 'get', 'delete']));
    const binding = manifests.find((m) => m.kind === 'RoleBinding' && m.metadata.namespace === ns) as Manifest & {
      roleRef: { kind: string; name: string };
    };
    expect(binding?.roleRef).toMatchObject({ kind: 'Role', name: 'eve-worker-runners' });
    expect(binding?.subjects).toEqual([{ kind: 'ServiceAccount', name: 'eve-worker', namespace: 'eve' }]);
  });
});
