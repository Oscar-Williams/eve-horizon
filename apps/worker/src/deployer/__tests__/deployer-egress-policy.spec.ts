import { beforeEach, describe, expect, it, vi } from 'vitest';
import yaml from 'yaml';
import { DeployerService } from '../deployer.service.js';

// egress.default_deny at deploy: the env namespace's egress policies are
// brought in line with the project's profile before any workload is applied,
// and the project's runner policies take in its env namespaces. Pods whose
// service account has Workload Identity carry the label that lets them reach
// the metadata server; apps reach the API on its public port.

const mocks = vi.hoisted(() => ({
  profiles: {} as Record<string, 'legacy' | 'audit' | 'strict'>,
  config: {} as Record<string, unknown>,
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: vi.fn(async () => 'legacy'),
  governingSecurityProfile: vi.fn(async (_db: unknown, ctx: { rule: string }) => mocks.profiles[ctx.rule] ?? 'legacy'),
}));

vi.mock('@eve/shared', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    loadConfig: () => ({
      EVE_API_URL: 'http://eve-api:4791',
      EVE_API_APP_URL: 'http://eve-api.eve.svc.cluster.local:4701',
      EVE_DEFAULT_DOMAIN: '',
      EVE_TCP_INGRESS_PROVIDER: 'none',
      EVE_COMPUTE_MODEL: 'k3s',
      ...mocks.config,
    }),
    resolveProjectSecrets: vi.fn(async () => ({ resolved: true, secrets: [], error: null })),
    mintServiceToken: vi.fn(async () => ({ access_token: 'svc-token' })),
  };
});

const params = {
  namespace: 'eve-acme-shop-prod',
  envId: 'env_prod',
  envName: 'prod',
  projectSlug: 'shop',
  projectId: 'proj_shop',
  orgId: 'org_acme',
  orgSlug: 'acme',
  releaseId: 'rel_1',
};

function deployerFor() {
  const order: string[] = [];
  const k8s = {
    createNamespace: vi.fn(async () => undefined),
    applyManifest: vi.fn(async () => { order.push('workloads'); }),
    listAliasIngresses: vi.fn(async () => []),
    listCustomDomainIngresses: vi.fn(async () => []),
    listSecrets: vi.fn(async () => []),
    deleteSecret: vi.fn(),
    deploymentExists: vi.fn(async () => false),
    getDeploymentStatus: vi.fn(async () => ({ ready: true, availableReplicas: 0, desiredReplicas: 0, conditions: [] })),
  };
  const deployer = new DeployerService(null as any, k8s as any);
  const logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
  const egress = {
    applyEnv: vi.fn(async (_env: unknown, profile: string) => { order.push(`env:${profile}`); return { profile, applied: [], removed: [] }; }),
    applyRunners: vi.fn(async (_projectId: string, profile: string) => { order.push(`runners:${profile}`); return { profile, applied: [], removed: [] }; }),
  };
  Object.assign(deployer as any, {
    logger,
    egress,
    environments: {
      findById: vi.fn().mockResolvedValue({ id: 'env_prod', project_id: 'proj_shop', name: 'prod', namespace: null, overrides_json: null }),
    },
    releases: {
      findById: vi.fn().mockResolvedValue({ id: 'rel_1', project_id: 'proj_shop', manifest_hash: 'h', image_digests_json: null }),
    },
    projects: { findById: vi.fn().mockResolvedValue({ id: 'proj_shop', org_id: 'org_acme', slug: 'shop', repo_url: null }) },
    orgs: { findById: vi.fn().mockResolvedValue({ id: 'org_acme', slug: 'acme' }) },
    manifests: { findByProjectAndHash: vi.fn().mockResolvedValue({ manifest_yaml: 'services: {}' }) },
    ensureImagePullSecret: vi.fn().mockResolvedValue(null),
    renderManifest: vi.fn(async () => {
      order.push('render');
      return {
        manifestYaml: 'kind: List',
        services: {},
        aliasIngresses: [],
        customDomainIngresses: [],
        desiredTcpIngressServices: [],
        serviceSecrets: [],
      };
    }),
  });
  return { deployer, k8s, egress, order, logger };
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profiles = {};
  mocks.config = {};
});

describe('deploy: egress policies', () => {
  it('writes the env policies under the project egress profile after render and before the workloads', async () => {
    mocks.profiles['egress.default_deny'] = 'audit';
    const { deployer, egress, order } = deployerFor();

    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });

    expect(egress.applyEnv).toHaveBeenCalledWith(
      { id: 'env_prod', projectId: 'proj_shop', name: 'prod', namespace: 'eve-acme-shop-prod' },
      'audit',
    );
    expect(egress.applyRunners).toHaveBeenCalledWith('proj_shop', 'audit');
    expect(order).toEqual(['render', 'env:audit', 'runners:audit', 'workloads']);
  });

  it('stops a strict deploy before any workload when the policies cannot be written', async () => {
    mocks.profiles['egress.default_deny'] = 'strict';
    const { deployer, egress, k8s } = deployerFor();
    egress.applyEnv.mockRejectedValueOnce(new Error('networkpolicies is forbidden'));

    await expect(deployer.deploy('env_prod', 'rel_1', { skipPreflight: true }))
      .rejects.toThrow(/egress policies.*networkpolicies is forbidden.*egress\.default_deny/s);
    expect(k8s.applyManifest).not.toHaveBeenCalled();
  });

  it('carries on under audit when the policies cannot be written, and says so', async () => {
    mocks.profiles['egress.default_deny'] = 'audit';
    const { deployer, egress, k8s, logger } = deployerFor();
    egress.applyEnv.mockRejectedValueOnce(new Error('networkpolicies is forbidden'));
    egress.applyRunners.mockRejectedValueOnce(new Error('networkpolicies is forbidden'));

    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });
    expect(k8s.applyManifest).toHaveBeenCalled();
    expect(logger.warn).toHaveBeenCalledWith(expect.stringMatching(/egress policies.*eve-acme-shop-prod.*forbidden/s));
  });
});

describe('render: Workload Identity pods and the API URL', () => {
  function renderer(mode: 'gcp-workload-identity' | 'irsa') {
    const deployer = new DeployerService(null as any, null as any);
    (deployer as any).logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
    (deployer as any).imageResolver.readImageConfig = vi.fn(async () => null);
    Object.assign((deployer as any).objectStoreProvisioner, {
      prepareObjectStorePlan: vi.fn(async () => ({
        scope: { namespace: params.namespace },
        binding: {
          mode,
          envVars: [],
          bindingHash: 'abc123',
          serviceAccount: { name: 'eve-app-env-prod', namespace: params.namespace, annotations: {} },
        },
        bucketsByService: new Map([['api', [{ name: 'uploads' }]]]),
      })),
      resolveObjectStoreBuckets: vi.fn(async () => []),
    });
    return deployer;
  }

  async function render(deployer: DeployerService) {
    const result = await (deployer as any).renderManifest({
      manifestYaml: yaml.stringify({
        services: { api: { image: 'api:1', ports: ['3000'] }, web: { image: 'web:1', ports: ['8080'] } },
      }),
      ...params,
    });
    return yaml.parseAllDocuments(result.manifestYaml).map((doc: any) => doc.toJSON())
      .filter((doc: any) => doc?.kind === 'Deployment');
  }

  it('labels the pods of a service whose account has Workload Identity, and no others', async () => {
    const deployments = await render(renderer('gcp-workload-identity'));
    const labels = Object.fromEntries(deployments.map((d: any) => [d.spec.template.spec.containers[0].name, d.spec.template.metadata.labels]));
    expect(labels.api['eve.workload_identity']).toBe('true');
    expect(labels.web['eve.workload_identity']).toBeUndefined();
  });

  it('leaves the label off a service account without Workload Identity', async () => {
    const deployments = await render(renderer('irsa'));
    for (const d of deployments) {
      expect(d.spec.template.metadata.labels['eve.workload_identity']).toBeUndefined();
    }
  });

  it('gives apps EVE_API_APP_URL as EVE_API_URL, never the internal port', async () => {
    const deployer = renderer('irsa');
    const { entries } = await (deployer as any).resolveServiceEnvEntries({ image: 'web:1' }, {
      envName: 'prod', projectId: 'proj_shop', orgId: 'org_acme', orgSlug: 'acme', projectSlug: 'shop', componentName: 'web',
    });
    expect(entries).toContainEqual({ name: 'EVE_API_URL', value: 'http://eve-api.eve.svc.cluster.local:4701' });

    mocks.config = { EVE_API_APP_URL: 'http://eve-api:4701' };
    const short = await (deployer as any).resolveServiceEnvEntries({ image: 'web:1' }, {
      envName: 'prod', projectId: 'proj_shop', orgId: 'org_acme', orgSlug: 'acme', projectSlug: 'shop', componentName: 'web',
    });
    expect(short.entries).toContainEqual({ name: 'EVE_API_URL', value: 'http://eve-api.eve.svc.cluster.local:4701' });
  });
});
