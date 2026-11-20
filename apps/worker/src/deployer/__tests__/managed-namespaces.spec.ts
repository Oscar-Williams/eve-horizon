import { beforeEach, describe, expect, it, vi } from 'vitest';
import { K8sService } from '../k8s.service.js';

/**
 * The worker's namespaces: every namespace it creates carries
 * `eve.horizon/managed=true` and a RoleBinding to the ClusterRole
 * `eve-worker-tenant`, through which alone the worker holds its namespaced
 * rights. At start-up it labels and binds the env namespaces earlier
 * releases made (they carry `eve.env_id`) that it can match to an
 * environment row, once.
 */
const db = vi.hoisted(() => ({
  envs: new Map<string, { id: string; project_id: string; name: string; namespace: string | null; status: string }>(),
  projects: new Map<string, { id: string; org_id: string; slug: string }>(),
  orgs: new Map<string, { id: string; slug: string }>(),
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  environmentQueries: () => ({ findById: async (id: string) => db.envs.get(id) ?? null }),
  projectQueries: () => ({ findById: async (id: string) => db.projects.get(id) ?? null }),
  orgQueries: () => ({ findById: async (id: string) => db.orgs.get(id) ?? null }),
}));

const ENV_LABELS = { 'eve.org_id': 'org_acme', 'eve.project_id': 'proj_shop', 'eve.env_id': 'env_prod', 'eve.env': 'prod' };
const BINDING = {
  apiVersion: 'rbac.authorization.k8s.io/v1',
  kind: 'RoleBinding',
  metadata: {
    name: 'eve-worker-tenant',
    namespace: 'eve-acme-shop-prod',
    labels: { 'app.kubernetes.io/managed-by': 'eve-horizon' },
  },
  roleRef: { apiGroup: 'rbac.authorization.k8s.io', kind: 'ClusterRole', name: 'eve-worker-tenant' },
  subjects: [{ kind: 'ServiceAccount', name: 'eve-worker', namespace: 'eve' }],
};

function k8sError(statusCode: number): Error {
  return Object.assign(new Error(`HTTP ${statusCode}`), { statusCode, response: { statusCode } });
}

function k8sWith() {
  const coreApi = {
    readNamespace: vi.fn(),
    createNamespace: vi.fn().mockResolvedValue({}),
    replaceNamespace: vi.fn().mockResolvedValue({}),
    patchNamespace: vi.fn().mockResolvedValue({}),
  };
  const rbacApi = {
    createNamespacedRoleBinding: vi.fn().mockResolvedValue({}),
    readNamespacedRoleBinding: vi.fn().mockRejectedValue(k8sError(404)),
  };
  const k8s = new K8sService();
  Object.assign(k8s as any, { coreApi, rbacApi, available: true });
  return { k8s, coreApi, rbacApi };
}

beforeEach(() => {
  vi.unstubAllEnvs();
  db.envs = new Map([['env_prod', { id: 'env_prod', project_id: 'proj_shop', name: 'prod', namespace: null, status: 'active' }]]);
  db.projects = new Map([['proj_shop', { id: 'proj_shop', org_id: 'org_acme', slug: 'shop' }]]);
  db.orgs = new Map([['org_acme', { id: 'org_acme', slug: 'acme' }]]);
});

describe('K8sService.createNamespace', () => {
  it('labels a new namespace managed and binds eve-worker-tenant in it', async () => {
    const { k8s, coreApi, rbacApi } = k8sWith();
    coreApi.readNamespace.mockRejectedValue(k8sError(404));

    await k8s.createNamespace('eve-acme-shop-prod', ENV_LABELS, { ownerLabel: 'eve.env_id' });

    expect(coreApi.createNamespace).toHaveBeenCalledWith({
      metadata: { name: 'eve-acme-shop-prod', labels: { ...ENV_LABELS, 'eve.horizon/managed': 'true' } },
    });
    expect(rbacApi.createNamespacedRoleBinding).toHaveBeenCalledWith('eve-acme-shop-prod', BINDING);
    expect(coreApi.createNamespace.mock.invocationCallOrder[0])
      .toBeLessThan(rbacApi.createNamespacedRoleBinding.mock.invocationCallOrder[0]);
  });

  it('adds the label to an env namespace it already owns with a merge patch (no update right needed), then binds', async () => {
    const { k8s, coreApi, rbacApi } = k8sWith();
    coreApi.readNamespace.mockResolvedValue({ body: { metadata: { name: 'eve-acme-shop-prod', labels: ENV_LABELS } } });
    rbacApi.createNamespacedRoleBinding.mockRejectedValue(k8sError(409));

    await k8s.createNamespace('eve-acme-shop-prod', ENV_LABELS, { ownerLabel: 'eve.env_id' });

    expect(coreApi.replaceNamespace).not.toHaveBeenCalled();
    expect(coreApi.patchNamespace).toHaveBeenCalledWith(
      'eve-acme-shop-prod',
      { metadata: { labels: { ...ENV_LABELS, 'eve.horizon/managed': 'true' } } },
      undefined, undefined, undefined, undefined, undefined,
      { headers: { 'Content-Type': 'application/merge-patch+json' } },
    );
    expect(rbacApi.createNamespacedRoleBinding).toHaveBeenCalledWith('eve-acme-shop-prod', BINDING);
  });

  it('binds the platform namespace the worker runs in', async () => {
    vi.stubEnv('EVE_K8S_NAMESPACE', 'eve-platform');
    const { k8s, coreApi, rbacApi } = k8sWith();
    coreApi.readNamespace.mockRejectedValue(k8sError(404));
    await k8s.createNamespace('eve-acme-shop-prod', ENV_LABELS, { ownerLabel: 'eve.env_id' });
    expect(rbacApi.createNamespacedRoleBinding.mock.calls[0][1].subjects)
      .toEqual([{ kind: 'ServiceAccount', name: 'eve-worker', namespace: 'eve-platform' }]);
  });

  it('removes a label with null through the same merge patch', async () => {
    const { k8s, coreApi } = k8sWith();
    await (k8s as any).setNamespaceLabels('eve-acme-shop-prod', { 'pod-security.kubernetes.io/enforce': null });
    expect(coreApi.patchNamespace).toHaveBeenCalledWith(
      'eve-acme-shop-prod',
      { metadata: { labels: { 'pod-security.kubernetes.io/enforce': null } } },
      undefined, undefined, undefined, undefined, undefined,
      { headers: { 'Content-Type': 'application/merge-patch+json' } },
    );
  });
});

describe('start-up reconcile of env namespaces from earlier releases', () => {
  type Ns = { name: string; labels: Record<string, string> };

  function cluster(namespaces: Ns[]) {
    const store = new Map(namespaces.map((ns) => [ns.name, { ...ns, labels: { ...ns.labels } }]));
    const bindings = new Set<string>();
    const writes: string[] = [];
    const api = {
      listNamespaces: vi.fn(async (selector: string) => {
        expect(selector).toBe('eve.env_id');
        return [...store.values()].filter((ns) => 'eve.env_id' in ns.labels).map((ns) => ({ name: ns.name, labels: { ...ns.labels } }));
      }),
      setNamespaceLabels: vi.fn(async (name: string, labels: Record<string, string>) => {
        Object.assign(store.get(name)!.labels, labels);
        writes.push(`label:${name}`);
      }),
      ensureTenantBinding: vi.fn(async (name: string) => {
        if (bindings.has(name)) return 'present' as const;
        bindings.add(name);
        writes.push(`bind:${name}`);
        return 'created' as const;
      }),
    };
    return { api, store, bindings, writes };
  }

  async function reconcilerFor(api: unknown) {
    const { ManagedNamespaceReconciler } = await import('../../network/managed-namespaces.js');
    return new ManagedNamespaceReconciler({} as never, api as never, { log: vi.fn(), warn: vi.fn() });
  }

  it('labels and binds each env namespace it can match to an environment row, once', async () => {
    db.envs.set('env_staging', { id: 'env_staging', project_id: 'proj_shop', name: 'staging', namespace: 'shop-staging-custom', status: 'active' });
    const c = cluster([
      { name: 'eve-acme-shop-prod', labels: ENV_LABELS },
      { name: 'shop-staging-custom', labels: { ...ENV_LABELS, 'eve.env_id': 'env_staging' } },
      // A row that no longer exists, and a label pointing at another env's namespace.
      { name: 'eve-acme-shop-old', labels: { ...ENV_LABELS, 'eve.env_id': 'env_gone' } },
      { name: 'eve-acme-other', labels: { ...ENV_LABELS } },
      { name: 'kube-system', labels: {} },
    ]);
    const reconciler = await reconcilerFor(c.api);

    const report = await reconciler.reconcile();
    expect(c.writes.sort()).toEqual([
      'bind:eve-acme-shop-prod', 'bind:shop-staging-custom', 'label:eve-acme-shop-prod', 'label:shop-staging-custom',
    ]);
    expect(c.store.get('eve-acme-shop-prod')!.labels['eve.horizon/managed']).toBe('true');
    expect(c.store.get('eve-acme-shop-old')!.labels['eve.horizon/managed']).toBeUndefined();
    expect(c.store.get('eve-acme-other')!.labels['eve.horizon/managed']).toBeUndefined();
    expect(report).toMatchObject({ labelled: 2, bound: 2, unmatched: 2 });

    c.writes.length = 0;
    await reconciler.reconcile();
    expect(c.writes).toEqual([]);
  });

  it('labels before it binds (the guard refuses writes in an unlabelled namespace), and binds a labelled one that lost its binding', async () => {
    const c = cluster([{ name: 'eve-acme-shop-prod', labels: ENV_LABELS }]);
    const reconciler = await reconcilerFor(c.api);
    await reconciler.reconcile();
    expect(c.writes).toEqual(['label:eve-acme-shop-prod', 'bind:eve-acme-shop-prod']);

    c.bindings.clear();
    c.writes.length = 0;
    await reconciler.reconcile();
    expect(c.writes).toEqual(['bind:eve-acme-shop-prod']);
  });

  it('skips a terminated environment and goes on after a failure', async () => {
    db.envs.set('env_old', { id: 'env_old', project_id: 'proj_shop', name: 'old', namespace: null, status: 'terminated' });
    const c = cluster([
      { name: 'eve-acme-shop-old', labels: { ...ENV_LABELS, 'eve.env_id': 'env_old' } },
      { name: 'eve-acme-shop-prod', labels: ENV_LABELS },
    ]);
    c.api.setNamespaceLabels.mockRejectedValueOnce(new Error('forbidden'));
    const reconciler = await reconcilerFor(c.api);
    const report = await reconciler.reconcile();
    expect(report).toMatchObject({ labelled: 0, unmatched: 1, failed: [{ namespace: 'eve-acme-shop-prod', error: 'forbidden' }] });
    expect(c.store.get('eve-acme-shop-old')!.labels['eve.horizon/managed']).toBeUndefined();
  });
});
