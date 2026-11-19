import { beforeEach, describe, expect, it, vi } from 'vitest';
import yaml from 'yaml';
import { DeployerService } from '../deployer.service.js';

// Resolved secret values, managed DB credentials and the service token reach
// a workload through a per-service Secret and secretKeyRef, never inline in
// the Deployment or Job spec.

const mocks = vi.hoisted(() => ({
  secrets: [] as Array<{ key: string; value: string; type: string }>,
  token: 'svc-token-1',
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: vi.fn(async () => 'legacy'),
  governingSecurityProfile: vi.fn(async () => 'legacy'),
}));

vi.mock('@eve/shared', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return {
    ...actual,
    loadConfig: () => ({
      EVE_API_URL: 'http://api.eve.test',
      EVE_DEFAULT_DOMAIN: '',
      EVE_TCP_INGRESS_PROVIDER: 'none',
      EVE_COMPUTE_MODEL: 'k3s',
    }),
    resolveProjectSecrets: vi.fn(async () => ({ resolved: true, secrets: mocks.secrets, error: null })),
    mintServiceToken: vi.fn(async () => ({ access_token: mocks.token })),
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

const web = {
  image: 'web:1',
  ports: ['3000'],
  environment: {
    DATABASE_URL: 'postgres://app:${secret.DB_PASSWORD}@db:5432/shop',
    STRIPE_KEY: '${secret.STRIPE_KEY}',
    REPORTS_URL: '${managed.reports.url}',
    LOG_LEVEL: 'info',
  },
};

function newDeployer() {
  const deployer = new DeployerService(null as any, null as any);
  (deployer as any).logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
  vi.spyOn(deployer as any, 'resolveManagedDbTenants').mockResolvedValue({
    managedValues: new Map([['reports.url', 'postgres://reports:managed-pw@reports:5432/reports']]),
    trustInputs: [],
  });
  return deployer;
}

async function render(services: Record<string, unknown>) {
  const result = await (newDeployer() as any).renderManifest({ manifestYaml: yaml.stringify({ services }), ...params });
  const docs = yaml.parseAllDocuments(result.manifestYaml).map((doc: any) => doc.toJSON());
  return { result, docs };
}

function decode(data: Record<string, string>): Record<string, string> {
  return Object.fromEntries(Object.entries(data).map(([k, v]) => [k, Buffer.from(v, 'base64').toString('utf8')]));
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.secrets = [
    { key: 'DB_PASSWORD', value: 'hunter2-db', type: 'env_var' },
    { key: 'STRIPE_KEY', value: 'sk_live_shop', type: 'env_var' },
  ];
  mocks.token = 'svc-token-1';
});

describe('DeployerService: per-service Secrets', () => {
  it('keeps every resolved value out of the Deployment', async () => {
    const { docs } = await render({ web });
    const deployment = docs.find((doc) => doc.kind === 'Deployment');
    const text = JSON.stringify(deployment);

    for (const value of ['hunter2-db', 'sk_live_shop', 'managed-pw', 'svc-token-1']) {
      expect(text).not.toContain(value);
    }
  });

  it('references each value through secretKeyRef to the service Secret, and keeps plain values inline', async () => {
    const { docs } = await render({ web });
    const env = docs.find((doc) => doc.kind === 'Deployment').spec.template.spec.containers[0].env;
    const byName = Object.fromEntries(env.map((entry: any) => [entry.name, entry]));

    for (const name of ['DATABASE_URL', 'STRIPE_KEY', 'REPORTS_URL', 'EVE_SERVICE_TOKEN']) {
      expect(byName[name]).toEqual({ name, valueFrom: { secretKeyRef: { name: 'prod-web-eve-secrets', key: name } } });
    }
    expect(byName.LOG_LEVEL).toEqual({ name: 'LOG_LEVEL', value: 'info' });
    expect(byName.EVE_PROJECT_ID).toEqual({ name: 'EVE_PROJECT_ID', value: 'proj_shop' });
  });

  it('writes the service Secret, labelled as Eve made it, before the Deployment', async () => {
    const { docs } = await render({ web });
    const secretIndex = docs.findIndex((doc) => doc.kind === 'Secret');
    const deploymentIndex = docs.findIndex((doc) => doc.kind === 'Deployment');
    const secret = docs[secretIndex];

    expect(secretIndex).toBeGreaterThanOrEqual(0);
    expect(secretIndex).toBeLessThan(deploymentIndex);
    expect(secret.metadata.name).toBe('prod-web-eve-secrets');
    expect(secret.type).toBe('Opaque');
    expect(secret.metadata.labels).toEqual(expect.objectContaining({
      'eve.service_secrets': 'true',
      'eve.project_id': 'proj_shop',
      'eve.env_id': 'env_prod',
      'eve.component': 'web',
    }));
    expect(decode(secret.data)).toEqual({
      DATABASE_URL: 'postgres://app:hunter2-db@db:5432/shop',
      STRIPE_KEY: 'sk_live_shop',
      REPORTS_URL: 'postgres://reports:managed-pw@reports:5432/reports',
      EVE_SERVICE_TOKEN: 'svc-token-1',
    });
  });

  it('rolls the pods when a value changes, through a hash of the Secret on the pod template', async () => {
    const hashOf = async () => {
      const { docs } = await render({ web });
      return docs.find((doc) => doc.kind === 'Deployment').spec.template.metadata.annotations['eve.secrets-sha256'];
    };

    const first = await hashOf();
    const same = await hashOf();
    mocks.secrets = [mocks.secrets[0], { key: 'STRIPE_KEY', value: 'sk_live_rotated', type: 'env_var' }];
    const rotated = await hashOf();

    expect(first).toMatch(/^[a-f0-9]{64}$/);
    expect(same).toBe(first);
    expect(rotated).not.toBe(first);
  });

  it('gives each service its own Secret and names them all in the result', async () => {
    const { result, docs } = await render({
      web,
      worker: { image: 'worker:1', environment: { STRIPE_KEY: '${secret.STRIPE_KEY}' } },
    });
    const secrets = docs.filter((doc) => doc.kind === 'Secret').map((doc) => doc.metadata.name).sort();

    expect(secrets).toEqual(['prod-web-eve-secrets', 'prod-worker-eve-secrets']);
    expect([...result.serviceSecrets].sort()).toEqual(['prod-web-eve-secrets', 'prod-worker-eve-secrets']);
  });
});

describe('DeployerService: pruning service Secrets', () => {
  function pruner(existing: Array<{ name: string; deployment: string }>, liveDeployments: string[]) {
    const k8s = {
      listSecrets: vi.fn(async () => existing.map((s) => ({
        name: s.name,
        labels: { 'eve.service_secrets': 'true' },
        annotations: { 'eve.deployment': s.deployment },
      }))),
      deleteSecret: vi.fn(async () => undefined),
      deploymentExists: vi.fn(async (_ns: string, name: string) => liveDeployments.includes(name)),
    };
    const deployer = new DeployerService(null as any, k8s as any);
    (deployer as any).logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
    return { deployer, k8s };
  }

  it('deletes the Secret of a service that is no longer deployed and has no Deployment left', async () => {
    const { deployer, k8s } = pruner([
      { name: 'prod-web-eve-secrets', deployment: 'prod-web' },
      { name: 'prod-old-eve-secrets', deployment: 'prod-old' },
    ], ['prod-web']);

    await (deployer as any).garbageCollectServiceSecrets('eve-acme-shop-prod', ['prod-web-eve-secrets'], {
      projectId: 'proj_shop',
      envId: 'env_prod',
    });

    expect(k8s.listSecrets).toHaveBeenCalledWith(
      'eve-acme-shop-prod',
      'eve.service_secrets=true,eve.project_id=proj_shop,eve.env_id=env_prod',
    );
    expect(k8s.deleteSecret).toHaveBeenCalledTimes(1);
    expect(k8s.deleteSecret).toHaveBeenCalledWith('eve-acme-shop-prod', 'prod-old-eve-secrets');
  });

  it('keeps the Secret while a Deployment of that service still runs', async () => {
    const { deployer, k8s } = pruner([{ name: 'prod-old-eve-secrets', deployment: 'prod-old' }], ['prod-old']);

    await (deployer as any).garbageCollectServiceSecrets('eve-acme-shop-prod', [], {
      projectId: 'proj_shop',
      envId: 'env_prod',
    });

    expect(k8s.deleteSecret).not.toHaveBeenCalled();
  });
});

describe('DeployerService: service job Secrets', () => {
  it('runs a job with its values in a Secret made for the run, removed afterwards', async () => {
    const calls: string[] = [];
    const k8s = {
      createNamespace: vi.fn(),
      applyManifest: vi.fn(async () => { calls.push('apply'); }),
      runJob: vi.fn(async () => {
        calls.push('run');
        return { jobName: 'prod-migrate-12345678', success: true, exitCode: 0, logs: '' };
      }),
      deleteSecret: vi.fn(async () => { calls.push('delete'); }),
    };
    const deployer = new DeployerService(null as any, k8s as any);
    (deployer as any).logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
    Object.assign(deployer, {
      environments: {
        findByProjectAndName: vi.fn().mockResolvedValue({
          id: 'env_prod', project_id: 'proj_shop', namespace: params.namespace, name: 'prod', overrides_json: null,
        }),
      },
      projects: { findById: vi.fn().mockResolvedValue({ id: 'proj_shop', org_id: 'org_acme', slug: 'shop', repo_url: null }) },
      orgs: { findById: vi.fn().mockResolvedValue({ id: 'org_acme', slug: 'acme' }) },
    });
    vi.spyOn(deployer as any, 'ensureImagePullSecret').mockResolvedValue(null);
    vi.spyOn(deployer as any, 'waitForJobDependencies').mockResolvedValue(undefined);

    await deployer.runJobService({
      projectId: 'proj_shop',
      envName: 'prod',
      manifestYaml: yaml.stringify({
        services: {
          migrate: {
            image: 'migrate:1',
            environment: { DATABASE_URL: 'postgres://app:${secret.DB_PASSWORD}@db:5432/shop' },
            'x-eve': { role: 'job' },
          },
        },
      }),
      serviceName: 'migrate',
      attemptId: 'attempt_12345678',
    });

    const job = k8s.runJob.mock.calls[0][1] as any;
    const env = job.spec.template.spec.containers[0].env;
    const secretDoc = yaml.parse(k8s.applyManifest.mock.calls[0][1] as string);

    expect(JSON.stringify(job)).not.toContain('hunter2-db');
    expect(env).toEqual(expect.arrayContaining([
      { name: 'DATABASE_URL', valueFrom: { secretKeyRef: { name: secretDoc.metadata.name, key: 'DATABASE_URL' } } },
    ]));
    expect(secretDoc.kind).toBe('Secret');
    expect(secretDoc.metadata.labels).toEqual(expect.objectContaining({ 'eve.job_secrets': 'true' }));
    expect(secretDoc.metadata.labels['eve.service_secrets']).toBeUndefined();
    expect(decode(secretDoc.data).DATABASE_URL).toBe('postgres://app:hunter2-db@db:5432/shop');
    expect(calls).toEqual(['apply', 'run', 'delete']);
    expect(k8s.deleteSecret).toHaveBeenCalledWith(params.namespace, secretDoc.metadata.name);
  });
});
