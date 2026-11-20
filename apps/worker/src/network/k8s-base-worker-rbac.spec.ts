import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parse, parseAllDocuments } from 'yaml';

/**
 * k8s/base: the worker's rights. Cluster-wide it may handle namespaces and
 * RoleBindings, and bind only `eve-worker-tenant`; everything namespaced
 * (Secrets, workloads, policies) comes from `eve-worker-tenant`, bound per
 * namespace: statically in the platform and runner namespaces, by the worker
 * in each namespace it manages. A ValidatingAdmissionPolicy holds the
 * worker's writes to managed namespaces. Its expressions are exercised on a
 * real API server by tests/k8s/worker-guard.kind.sh.
 */
type Rule = { apiGroups: string[]; resources: string[]; verbs: string[]; resourceNames?: string[] };
type Manifest = {
  apiVersion: string;
  kind: string;
  metadata: { name: string; namespace?: string; labels?: Record<string, string> };
  rules?: Rule[];
  roleRef?: { kind: string; name: string };
  subjects?: Array<{ kind: string; name: string; namespace?: string }>;
  spec?: any;
};

const baseDir = join(__dirname, '..', '..', '..', '..', 'k8s', 'base');
const manifests: Manifest[] = readdirSync(baseDir)
  .filter((file) => file.endsWith('.yaml'))
  .flatMap((file) => parseAllDocuments(readFileSync(join(baseDir, file), 'utf8'))
    .map((doc) => doc.toJSON() as Manifest | null)
    .filter((doc): doc is Manifest => doc !== null));
const kustomization = parse(readFileSync(join(baseDir, 'kustomization.yaml'), 'utf8')) as { resources: string[] };

const WORKER = { kind: 'ServiceAccount', name: 'eve-worker', namespace: 'eve' };
const isWorker = (s: { kind: string; name: string; namespace?: string }) =>
  s.kind === WORKER.kind && s.name === WORKER.name && s.namespace === WORKER.namespace;
const of = (kind: string) => manifests.filter((m) => m.kind === kind);
const clusterRole = (name: string) => of('ClusterRole').find((m) => m.metadata.name === name);

/** The ClusterRoles bound to the worker cluster-wide. */
function clusterWideRoles(): Manifest[] {
  return of('ClusterRoleBinding')
    .filter((b) => (b.subjects ?? []).some(isWorker))
    .map((b) => clusterRole(b.roleRef!.name))
    .filter((r): r is Manifest => r !== undefined);
}

describe('k8s/base: the worker cluster-wide', () => {
  it('holds namespaces, RoleBindings and bind on eve-worker-tenant, and nothing else', () => {
    const roles = clusterWideRoles();
    expect(roles.length).toBeGreaterThan(0);
    const rules = roles.flatMap((r) => r.rules ?? []);
    for (const rule of rules) {
      for (const field of [rule.apiGroups, rule.resources, rule.verbs]) expect(field).not.toContain('*');
    }
    const grants = rules.flatMap((rule) => rule.resources.map((resource) => ({ resource, rule })));
    expect([...new Set(grants.map((g) => g.resource))].sort()).toEqual(['clusterroles', 'namespaces', 'rolebindings']);

    const namespaces = rules.filter((r) => r.resources.includes('namespaces'));
    expect(namespaces.flatMap((r) => r.verbs).sort()).toEqual(['create', 'delete', 'get', 'list', 'patch', 'watch']);
    const bindings = rules.filter((r) => r.resources.includes('rolebindings'));
    expect(bindings.flatMap((r) => r.apiGroups)).toEqual(['rbac.authorization.k8s.io']);
    expect(bindings.flatMap((r) => r.verbs).sort()).toEqual(['create', 'delete', 'get', 'list']);
    const bind = rules.filter((r) => r.resources.includes('clusterroles'));
    expect(bind).toEqual([{ apiGroups: ['rbac.authorization.k8s.io'], resources: ['clusterroles'], verbs: ['bind'], resourceNames: ['eve-worker-tenant'] }]);
  });

  it('holds no Secret rule, and the old all-namespace role is gone', () => {
    for (const role of clusterWideRoles()) {
      expect((role.rules ?? []).some((r) => r.resources.includes('secrets'))).toBe(false);
    }
    expect(clusterRole('eve-worker')).toBeUndefined();
    expect(of('ClusterRoleBinding').find((b) => b.metadata.name === 'eve-worker')).toBeUndefined();
  });
});

describe('k8s/base: eve-worker-tenant', () => {
  it("holds today's namespaced rights, and the FQDN policies", () => {
    const role = clusterRole('eve-worker-tenant');
    expect(role).toBeDefined();
    const covers = (group: string, resource: string) => (role!.rules ?? [])
      .some((r) => r.apiGroups.includes(group) && r.resources.includes(resource) && ['create', 'delete', 'get', 'list'].every((v) => r.verbs.includes(v)));
    for (const [group, resource] of [
      ['', 'pods'], ['', 'services'], ['', 'configmaps'], ['', 'secrets'], ['', 'persistentvolumeclaims'],
      ['apps', 'deployments'], ['apps', 'statefulsets'], ['batch', 'jobs'],
      ['networking.k8s.io', 'ingresses'], ['networking.k8s.io', 'networkpolicies'], ['networking.gke.io', 'fqdnnetworkpolicies'],
    ]) {
      expect(covers(group, resource), `${group}/${resource}`).toBe(true);
    }
  });

  it('is bound to the worker only per namespace: statically in eve and eve-runners', () => {
    expect(of('ClusterRoleBinding').some((b) => b.roleRef?.name === 'eve-worker-tenant')).toBe(false);
    const statics = of('RoleBinding').filter((b) => b.roleRef?.kind === 'ClusterRole' && b.roleRef.name === 'eve-worker-tenant');
    expect(statics.map((b) => b.metadata.namespace).sort()).toEqual(['eve', 'eve-runners']);
    for (const binding of statics) expect(binding.subjects).toEqual([WORKER]);
  });
});

describe('k8s/base: the worker namespace guard', () => {
  const policy = () => of('ValidatingAdmissionPolicy').find((m) => m.metadata.name === 'eve-worker-namespace-guard');

  it('is in the kustomization, fails closed and denies', () => {
    expect(kustomization.resources).toContain('worker-admission-policy.yaml');
    expect(policy()?.spec.failurePolicy).toBe('Fail');
    const binding = of('ValidatingAdmissionPolicyBinding').find((m) => m.spec?.policyName === 'eve-worker-namespace-guard');
    expect(binding?.spec.validationActions).toEqual(['Deny']);
  });

  it("matches only the worker's writes, on every resource", () => {
    const spec = policy()!.spec;
    expect(spec.matchConstraints.resourceRules).toEqual([
      { apiGroups: ['*'], apiVersions: ['*'], operations: ['CREATE', 'UPDATE', 'DELETE'], resources: ['*/*'] },
    ]);
    const conditions = spec.matchConditions.map((c: { expression: string }) => c.expression).join(' ');
    expect(conditions).toContain("'system:serviceaccount:eve:eve-worker'");
  });

  it('has a refusal for each rule, naming the labels and the role the worker code uses', () => {
    const text = JSON.stringify(policy()!.spec);
    for (const needle of ["'eve.horizon/managed'", "'eve.env_id'", "'eve-worker-tenant'", "'eve-runners'", "namespaceObject", 'oldObject']) {
      expect(text, needle).toContain(needle);
    }
    const messages = policy()!.spec.validations.map((v: { message?: string; messageExpression?: string }) => v.message ?? v.messageExpression);
    expect(messages.join('\n')).toMatch(/managed/);
    expect(policy()!.spec.validations.length).toBeGreaterThanOrEqual(5);
  });
});
