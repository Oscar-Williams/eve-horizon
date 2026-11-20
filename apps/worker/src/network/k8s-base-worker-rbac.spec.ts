import { existsSync, readdirSync, readFileSync } from 'node:fs';
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

const k8sDir = join(__dirname, '..', '..', '..', '..', 'k8s');
const baseDir = join(k8sDir, 'base');
/** The admission policies: their own kustomization, applied after the worker's start-up reconcile. */
const admissionDir = join(k8sDir, 'admission');
const read = (dir: string): Manifest[] => (existsSync(dir) ? readdirSync(dir) : [])
  .filter((file) => file.endsWith('.yaml') && file !== 'kustomization.yaml')
  .flatMap((file) => parseAllDocuments(readFileSync(join(dir, file), 'utf8'))
    .map((doc) => doc.toJSON() as Manifest | null)
    .filter((doc): doc is Manifest => doc !== null));
const manifests: Manifest[] = [...read(baseDir), ...read(admissionDir)];
const kustomization = parse(readFileSync(join(baseDir, 'kustomization.yaml'), 'utf8')) as { resources: string[] };
const admissionKustomization = (): { resources: string[] } | null => (existsSync(join(admissionDir, 'kustomization.yaml'))
  ? parse(readFileSync(join(admissionDir, 'kustomization.yaml'), 'utf8')) as { resources: string[] }
  : null);

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

  it('is bound to the worker only per namespace: statically in eve-runners, never in the platform namespace', () => {
    expect(of('ClusterRoleBinding').some((b) => b.roleRef?.name === 'eve-worker-tenant')).toBe(false);
    const statics = of('RoleBinding').filter((b) => b.roleRef?.kind === 'ClusterRole' && b.roleRef.name === 'eve-worker-tenant');
    expect(statics.map((b) => b.metadata.namespace).sort()).toEqual(['eve-runners']);
    for (const binding of statics) expect(binding.subjects).toEqual([WORKER]);
  });

  it('holds no DaemonSets (the worker never makes one)', () => {
    expect((clusterRole('eve-worker-tenant')!.rules ?? []).some((r) => r.resources.includes('daemonsets'))).toBe(false);
  });
});

describe('k8s/base: the worker in the platform namespace', () => {
  /** Every rule bound to the worker in eve, through a Role or a ClusterRole. */
  function platformRules(): Rule[] {
    return of('RoleBinding')
      .filter((b) => b.metadata.namespace === 'eve' && (b.subjects ?? []).some(isWorker))
      .flatMap((b) => (b.roleRef!.kind === 'Role'
        ? of('Role').find((r) => r.metadata.name === b.roleRef!.name && r.metadata.namespace === 'eve')
        : clusterRole(b.roleRef!.name))?.rules ?? []);
  }
  const verbsOn = (resource: string) => [...new Set(platformRules()
    .filter((r) => r.resources.includes(resource)).flatMap((r) => r.verbs))].sort();

  it('holds only what it uses there: runner pods and claims, kaniko Jobs and their Secrets, runner policies', () => {
    const resources = [...new Set(platformRules().flatMap((r) => r.resources))].sort();
    expect(resources).toEqual(['fqdnnetworkpolicies', 'jobs', 'networkpolicies', 'persistentvolumeclaims', 'pods', 'secrets', 'services']);
    for (const rule of platformRules()) {
      for (const field of [rule.apiGroups, rule.resources, rule.verbs]) expect(field).not.toContain('*');
    }
  });

  it('never execs, and creates and deletes Secrets without reading any (eve-app and the rest stay out of reach)', () => {
    expect(platformRules().some((r) => r.resources.includes('pods/exec'))).toBe(false);
    expect(verbsOn('secrets')).toEqual(['create', 'delete']);
    expect(verbsOn('services')).toEqual(['get']);
    expect(verbsOn('pods')).not.toContain('update');
  });
});

describe('k8s/base: the worker namespace guard', () => {
  const policy = () => of('ValidatingAdmissionPolicy').find((m) => m.metadata.name === 'eve-worker-namespace-guard');

  it('is in its own kustomization (k8s/admission), not in base, fails closed and denies', () => {
    expect(kustomization.resources).not.toContain('worker-admission-policy.yaml');
    expect(admissionKustomization()?.resources).toEqual(expect.arrayContaining(['worker-admission-policy.yaml', 'orchestrator-admission-policy.yaml']));
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

  it('refuses every RoleBinding in the static namespaces (eve-worker-tenant in eve would give back its Secrets)', () => {
    const rules = (policy()!.spec.validations as Array<{ expression: string }>)
      .filter((v) => v.expression.includes('variables.isRoleBinding'));
    expect(rules.some((v) => v.expression.includes('variables.staticNamespaces'))).toBe(true);
  });
});

describe('k8s/admission: the worker workload guard', () => {
  const policy = () => of('ValidatingAdmissionPolicy').find((m) => m.metadata.name === 'eve-worker-workload-guard');

  it('fails closed, denies, and matches the worker creating or changing pods and every pod template', () => {
    expect(policy()?.spec.failurePolicy).toBe('Fail');
    const binding = of('ValidatingAdmissionPolicyBinding').find((m) => m.spec?.policyName === 'eve-worker-workload-guard');
    expect(binding?.spec.validationActions).toEqual(['Deny']);
    const rules = policy()!.spec.matchConstraints.resourceRules as Array<{ apiGroups: string[]; resources: string[]; operations: string[] }>;
    const covered = rules.flatMap((r) => r.resources);
    for (const resource of ['pods', 'deployments', 'replicasets', 'statefulsets', 'daemonsets', 'jobs', 'cronjobs', 'sandboxtemplates']) {
      expect(covered, resource).toContain(resource);
    }
    for (const rule of rules) expect(rule.operations.sort()).toEqual(['CREATE', 'UPDATE']);
    expect(JSON.stringify(policy()!.spec.matchConditions)).toContain("'system:serviceaccount:eve:eve-worker'");
  });

  it('refuses privileged pods, host namespaces and paths, other service accounts and DaemonSets, and guards the platform namespace', () => {
    const text = JSON.stringify(policy()!.spec);
    for (const needle of [
      'hostNetwork', 'hostPID', 'hostIPC', 'hostPath', 'privileged', 'hostPort', 'capabilities',
      'serviceAccountName', "'default'", "'eve-runner'", "'eve-app'", "'eve-app-'", "'daemonsets'",
      "'kaniko-cfg-'", "'eve-ws-'", "'eve-org-fs-'", "'app.kubernetes.io/name'",
    ]) {
      expect(text, needle).toContain(needle);
    }
  });

  it('holds every container, init and ephemeral ones included, to Pod Security baseline', () => {
    const text = JSON.stringify(policy()!.spec);
    for (const needle of [
      'ephemeralContainers', 'seccompProfile', "'Unconfined'", 'appArmorProfile',
      "'container.apparmor.security.beta.kubernetes.io/'", 'procMount', "'Default'", 'sysctls',
      "'kernel.shm_rmid_forced'", 'seLinuxOptions', "'container_t'", 'hostProcess',
    ]) {
      expect(text, needle).toContain(needle);
    }
  });
});

describe('k8s/admission: the worker platform guard', () => {
  const policy = () => of('ValidatingAdmissionPolicy').find((m) => m.metadata.name === 'eve-worker-platform-guard');

  it("fails closed, denies, and matches every write of the worker's in the platform namespace", () => {
    expect(policy()?.spec.failurePolicy).toBe('Fail');
    const binding = of('ValidatingAdmissionPolicyBinding').find((m) => m.spec?.policyName === 'eve-worker-platform-guard');
    expect(binding?.spec.validationActions).toEqual(['Deny']);
    expect(policy()!.spec.matchConstraints.resourceRules).toEqual([
      { apiGroups: ['*'], apiVersions: ['*'], operations: ['CREATE', 'UPDATE', 'DELETE'], resources: ['*/*'] },
    ]);
    const conditions = JSON.stringify(policy()!.spec.matchConditions);
    expect(conditions).toContain("'system:serviceaccount:eve:eve-worker'");
    expect(conditions).toContain("request.namespace == 'eve'");
  });

  it('holds Secrets, claims, pods, Jobs and policies there to what the worker makes, before and after the change', () => {
    const text = JSON.stringify(policy()!.spec);
    for (const needle of [
      "'kaniko-cfg-'", "'eve-ws-'", "'eve-org-fs-'", 'dataSource', 'dataSourceRef', 'volumeName',
      "'eve.type'", "'runner'", "'eve.horizon/component'", "'kaniko-build'", "'eve.horizon/egress'", 'oldObject',
    ]) {
      expect(text, needle).toContain(needle);
    }
  });

  it('is joined by the workload guard refusing ephemeral volumes anywhere', () => {
    const workload = of('ValidatingAdmissionPolicy').find((m) => m.metadata.name === 'eve-worker-workload-guard')!;
    expect(JSON.stringify(workload.spec)).toContain('ephemeral');
  });
});

describe('k8s/admission: the namespace guard refuses escalation through Secrets and namespace labels', () => {
  it('refuses service account token Secrets and a privileged Pod Security enforce', () => {
    const text = JSON.stringify(of('ValidatingAdmissionPolicy').find((m) => m.metadata.name === 'eve-worker-namespace-guard')!.spec);
    expect(text).toContain('kubernetes.io/service-account-token');
    expect(text).toContain('pod-security.kubernetes.io/enforce');
    expect(text).toContain("'privileged'");
  });
});

describe('k8s/base: the orchestrator', () => {
  it('scales Deployments and patches nothing else', () => {
    const role = clusterRole('eve-orchestrator')!;
    const writes = (role.rules ?? []).filter((r) => r.verbs.some((v) => ['create', 'update', 'patch', 'delete'].includes(v)));
    expect(writes).toEqual([{ apiGroups: ['apps'], resources: ['deployments/scale'], verbs: ['patch'] }]);
  });

  it('is held by an admission policy to scaling to zero in managed namespaces', () => {
    const policy = of('ValidatingAdmissionPolicy').find((m) => m.metadata.name === 'eve-orchestrator-scale-guard');
    expect(policy?.spec.failurePolicy).toBe('Fail');
    const binding = of('ValidatingAdmissionPolicyBinding').find((m) => m.spec?.policyName === 'eve-orchestrator-scale-guard');
    expect(binding?.spec.validationActions).toEqual(['Deny']);
    const text = JSON.stringify(policy!.spec);
    for (const needle of ["'system:serviceaccount:eve:eve-orchestrator'", "'scale'", "'eve.horizon/managed'", 'replicas']) {
      expect(text, needle).toContain(needle);
    }
  });
});
