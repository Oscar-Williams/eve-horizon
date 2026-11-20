import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'node:fs';
import yaml from 'yaml';
import { DeployerService } from '../deployer.service.js';
import { ImageResolver } from '../image-resolver.js';

// Rule isolation.pod_security: under `strict` tenant pods and service job
// pods get the restricted security context with a numeric user; under
// `audit` each service's image user and what strict would add are recorded.

const mocks = vi.hoisted(() => ({
  profile: 'legacy' as 'legacy' | 'audit' | 'strict',
  decide: vi.fn(),
  governing: vi.fn(),
  config: {} as Record<string, unknown>,
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: mocks.decide,
  governingSecurityProfile: mocks.governing,
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

/** Image config `User` per image, as `crane config` would report it; absent: unreadable. */
let imageUsers: Record<string, string> = {};

function newDeployer(k8s: unknown = null) {
  const deployer = new DeployerService(null as any, k8s as any);
  (deployer as any).logger = { warn: vi.fn(), log: vi.fn(), error: vi.fn(), debug: vi.fn() };
  // egress.default_deny has its own spec (deployer-egress-policy.spec.ts).
  (deployer as any).egress = { applyEnv: vi.fn(async () => ({})), applyRunners: vi.fn(async () => ({})) };
  const readImageConfig = vi.fn(async (image: string) => (image in imageUsers ? { user: imageUsers[image] } : null));
  (deployer as any).imageResolver.readImageConfig = readImageConfig;
  return { deployer, readImageConfig };
}

async function render(services: Record<string, unknown>, profile = mocks.profile) {
  const { deployer, readImageConfig } = newDeployer();
  const result = await (deployer as any).renderManifest({
    manifestYaml: yaml.stringify({ services }),
    ...params,
    podSecurity: profile,
  });
  const docs = yaml.parseAllDocuments(result.manifestYaml).map((doc: any) => doc.toJSON());
  const pods = Object.fromEntries(
    docs.filter((doc: any) => doc.kind === 'Deployment')
      .map((doc: any) => [doc.spec.template.spec.containers[0].name, doc.spec.template.spec]),
  );
  return { result, pods, readImageConfig };
}

function findings() {
  return mocks.decide.mock.calls
    .filter((call) => call[1] === 'isolation.pod_security')
    .map((call) => call[2]);
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profile = 'legacy';
  mocks.config = {};
  mocks.decide.mockImplementation(async () => mocks.profile);
  // Rule set 3's egress.allow_hosts and isolation.pod_security_admission have
  // their own specs (deployer-allow-hosts, deployer-pod-security-admission).
  mocks.governing.mockImplementation(async (_db: unknown, ctx: { rule?: string }) =>
    (ctx?.rule === 'egress.allow_hosts' || ctx?.rule === 'isolation.pod_security_admission' ? 'legacy' : mocks.profile));
  imageUsers = { 'web:1': '1000:1001', 'api:1': 'node', 'root:1': '', 'nginx:1': '0' };
});

describe('isolation.pod_security under strict', () => {
  beforeEach(() => { mocks.profile = 'strict'; });

  it('gives the pod the restricted context with the image numeric user', async () => {
    const { pods } = await render({ web: { image: 'web:1', ports: ['3000'] } });
    const pod = pods.web;

    expect(pod.automountServiceAccountToken).toBe(false);
    expect(pod.securityContext).toEqual({ seccompProfile: { type: 'RuntimeDefault' } });
    expect(pod.containers[0].securityContext).toEqual({
      allowPrivilegeEscalation: false,
      capabilities: { drop: ['ALL'] },
      runAsNonRoot: true,
      runAsUser: 1000,
      runAsGroup: 1001,
    });
  });

  it('uses x-eve.security.run_as_user and run_as_group for an image that names its user', async () => {
    const { pods } = await render({
      api: { image: 'api:1', ports: ['3000'], 'x-eve': { security: { run_as_user: 1000, run_as_group: 1000 } } },
    });

    expect(pods.api.containers[0].securityContext).toEqual(expect.objectContaining({
      runAsNonRoot: true,
      runAsUser: 1000,
      runAsGroup: 1000,
    }));
  });

  it('refuses the deploy for an image that names its user, naming the manifest fields', async () => {
    await expect(render({ api: { image: 'api:1', ports: ['3000'] } }))
      .rejects.toThrow(/api.*x-eve\.security\.run_as_user.*run_as_group.*isolation\.pod_security/s);
    expect(findings()).toEqual([expect.objectContaining({
      projectId: 'proj_shop',
      governing: 'project',
      actorType: 'deployer',
      actorId: 'prod/api',
      detail: expect.objectContaining({ service: 'api', image_user: 'name', strict_blocker: 'named_user' }),
    })]);
  });

  it('refuses an image that runs as root, and one whose config cannot be read', async () => {
    await expect(render({ root: { image: 'root:1' } })).rejects.toThrow(/root.*run_as_user/s);
    await expect(render({ nginx: { image: 'nginx:1' } })).rejects.toThrow(/nginx.*run_as_user/s);
    await expect(render({ other: { image: 'unknown:1' } })).rejects.toThrow(/other.*run_as_user/s);
  });

  it('honours run_as_root and allowed capabilities, and marks the namespace baseline', async () => {
    const { pods, result } = await render({
      nginx: {
        image: 'nginx:1',
        ports: ['80'],
        'x-eve': { security: { run_as_root: true, capabilities: ['NET_BIND_SERVICE', 'CHOWN', 'SETUID', 'SETGID'] } },
      },
    });
    const container = pods.nginx.containers[0];

    expect(container.securityContext.runAsNonRoot).toBeUndefined();
    expect(container.securityContext.runAsUser).toBeUndefined();
    expect(container.securityContext.allowPrivilegeEscalation).toBe(false);
    expect(container.securityContext.capabilities).toEqual({
      drop: ['ALL'],
      add: ['NET_BIND_SERVICE', 'CHOWN', 'SETUID', 'SETGID'],
    });
    expect(pods.nginx.securityContext).toEqual({ seccompProfile: { type: 'RuntimeDefault' } });
    expect(result.podSecurityLevel).toBe('baseline');
  });

  it('counts service jobs in the namespace level: a migrate job that runs as root makes it baseline', async () => {
    // The job pod starts later in the same namespace; an enforce at
    // restricted would refuse it.
    const { result } = await render({
      web: { image: 'web:1', ports: ['8080'] },
      migrate: { image: 'web:1', 'x-eve': { role: 'job', security: { run_as_root: true } } },
    });
    expect(result.podSecurityLevel).toBe('baseline');
  });

  it('keeps the namespace restricted when every service fits it', async () => {
    const { result } = await render({
      web: { image: 'web:1', ports: ['8080'], 'x-eve': { security: { capabilities: ['NET_BIND_SERVICE'] } } },
    });
    expect(result.podSecurityLevel).toBe('restricted');
  });

  it('refuses an invalid x-eve.security that an environment override brings in', async () => {
    const { deployer } = newDeployer();
    await expect((deployer as any).renderManifest({
      manifestYaml: yaml.stringify({ services: { web: { image: 'web:1', ports: ['3000'] } } }),
      ...params,
      envOverrides: { services: { web: { 'x-eve': { security: { run_as_user: 'node' } } } } },
      podSecurity: 'strict',
    })).rejects.toThrow(/x-eve\.security of web is invalid/);
  });

  it('refuses networking.egress: stable', async () => {
    await expect(render({
      web: { image: 'web:1', ports: ['3000'], 'x-eve': { networking: { egress: 'stable' } } },
    })).rejects.toThrow(/web.*egress.*stable/s);
  });

  it('gives a service job pod the same context', async () => {
    const runJob = vi.fn().mockResolvedValue({ jobName: 'job', success: true, exitCode: 0, logs: '' });
    const { deployer } = newDeployer({ createNamespace: vi.fn(), runJob, applyManifest: vi.fn(), deleteSecret: vi.fn() });
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
      manifestYaml: yaml.stringify({ services: { migrate: { image: 'web:1', 'x-eve': { role: 'job' } } } }),
      serviceName: 'migrate',
      attemptId: 'attempt_12345678',
    });

    const pod = runJob.mock.calls[0][1].spec.template.spec;
    expect(pod.automountServiceAccountToken).toBe(false);
    expect(pod.securityContext).toEqual({ seccompProfile: { type: 'RuntimeDefault' } });
    expect(pod.containers[0].securityContext).toEqual(expect.objectContaining({
      runAsNonRoot: true,
      runAsUser: 1000,
      allowPrivilegeEscalation: false,
    }));
  });

  it('refuses a service job whose image names its user', async () => {
    const runJob = vi.fn();
    const { deployer } = newDeployer({ createNamespace: vi.fn(), runJob, applyManifest: vi.fn(), deleteSecret: vi.fn() });
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

    await expect(deployer.runJobService({
      projectId: 'proj_shop',
      envName: 'prod',
      manifestYaml: yaml.stringify({ services: { migrate: { image: 'api:1', 'x-eve': { role: 'job' } } } }),
      serviceName: 'migrate',
      attemptId: 'attempt_12345678',
    })).rejects.toThrow(/migrate.*run_as_user/s);
    expect(runJob).not.toHaveBeenCalled();
  });
});

describe('isolation.pod_security under audit', () => {
  beforeEach(() => { mocks.profile = 'audit'; });

  it('changes no pod, and records the image user, low ports and what strict would add', async () => {
    const { pods } = await render({
      web: { image: 'web:1', ports: ['3000'] },
      api: { image: 'api:1', ports: ['80', '3000'] },
    });

    expect(pods.web.securityContext).toBeUndefined();
    expect(pods.web.automountServiceAccountToken).toBeUndefined();
    expect(pods.web.containers[0].securityContext).toBeUndefined();

    const byService = Object.fromEntries(findings().map((f) => [f.detail.service, f]));
    expect(byService.web.detail).toEqual(expect.objectContaining({
      env: 'prod',
      image_user: 'numeric',
      strict_blocker: null,
    }));
    expect(byService.web.detail.would_add).toContain('run_as_user');
    expect(byService.api.actorId).toBe('prod/api');
    expect(byService.api.detail).toEqual(expect.objectContaining({
      image_user: 'name',
      user: 'node',
      low_ports: '80',
      strict_blocker: 'named_user',
    }));
  });

  it('does not refuse an invalid x-eve.security that an environment override brings in', async () => {
    const { deployer } = newDeployer();
    const result = await (deployer as any).renderManifest({
      manifestYaml: yaml.stringify({ services: { web: { image: 'web:1', ports: ['3000'] } } }),
      ...params,
      envOverrides: { services: { web: { 'x-eve': { security: { run_as_user: 'node' } } } } },
      podSecurity: 'audit',
    });

    expect(result.manifestYaml).toContain('kind: Deployment');
    expect(findings()[0].detail).toEqual(expect.objectContaining({ service: 'web', image_user: 'numeric' }));
  });

  it('records stable egress as a strict blocker without refusing', async () => {
    await render({ web: { image: 'web:1', 'x-eve': { networking: { egress: 'stable' } } } });
    expect(findings()[0].detail.strict_blocker).toBe('stable_egress');
  });
});

describe('isolation.pod_security under legacy', () => {
  it('reads no image and records nothing', async () => {
    const { pods, readImageConfig } = await render({ api: { image: 'api:1', ports: ['3000'] } }, 'legacy');

    expect(readImageConfig).not.toHaveBeenCalled();
    expect(mocks.decide).not.toHaveBeenCalled();
    expect(pods.api.securityContext).toBeUndefined();
    expect(pods.api.containers[0].securityContext).toBeUndefined();
  });
});

describe('deploy: namespace Pod Security labels', () => {
  function deployerFor(level: 'restricted' | 'baseline') {
    const k8s = {
      createNamespace: vi.fn(async () => undefined),
      applyManifest: vi.fn(async () => undefined),
      listAliasIngresses: vi.fn(async () => []),
      listCustomDomainIngresses: vi.fn(async () => []),
      listSecrets: vi.fn(async () => []),
      deleteSecret: vi.fn(),
      deploymentExists: vi.fn(async () => false),
      getDeploymentStatus: vi.fn(async () => ({ ready: true, availableReplicas: 0, desiredReplicas: 0, conditions: [] })),
    };
    const { deployer } = newDeployer(k8s);
    Object.assign(deployer as any, {
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
      renderManifest: vi.fn().mockResolvedValue({
        manifestYaml: '',
        services: {},
        aliasIngresses: [],
        customDomainIngresses: [],
        desiredTcpIngressServices: [],
        serviceSecrets: [],
        podSecurityLevel: level,
      }),
    });
    return { deployer, k8s };
  }

  it('labels the namespace warn and audit, never enforce, at a strict deploy', async () => {
    mocks.profile = 'strict';
    const { deployer, k8s } = deployerFor('baseline');

    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });

    expect((deployer as any).renderManifest).toHaveBeenCalledWith(expect.objectContaining({ podSecurity: 'strict' }));
    const labels = Object.assign({}, ...k8s.createNamespace.mock.calls.map((call: any[]) => call[1] ?? {}));
    expect(labels['pod-security.kubernetes.io/warn']).toBe('baseline');
    expect(labels['pod-security.kubernetes.io/audit']).toBe('baseline');
    expect(Object.keys(labels).filter((key) => key.startsWith('pod-security.kubernetes.io/enforce'))).toEqual([]);
    for (const call of k8s.createNamespace.mock.calls as unknown[][]) {
      expect(call[2]).toEqual({ ownerLabel: 'eve.env_id' });
    }
  });

  it('leaves the namespace labels alone under audit', async () => {
    mocks.profile = 'audit';
    const { deployer, k8s } = deployerFor('restricted');

    await deployer.deploy('env_prod', 'rel_1', { skipPreflight: true });

    const labels = Object.assign({}, ...k8s.createNamespace.mock.calls.map((call: any[]) => call[1] ?? {}));
    expect(Object.keys(labels).filter((key) => key.startsWith('pod-security.kubernetes.io/'))).toEqual([]);
  });
});

describe('ImageResolver.readImageConfig', () => {
  it('reads the image user with crane config, using the pull credentials for that call only', async () => {
    let seenConfig: string | null = null;
    let seenDir: string | undefined;
    const run = vi.fn(async (args: string[], env: Record<string, string | undefined>) => {
      seenDir = env.DOCKER_CONFIG;
      seenConfig = seenDir ? fs.readFileSync(`${seenDir}/config.json`, 'utf8') : null;
      return JSON.stringify({ config: { User: '1000:1000', ExposedPorts: { '3000/tcp': {} } } });
    });
    const resolver = new (ImageResolver as any)(null, { warn: vi.fn(), log: vi.fn() }, run);
    const dockerConfig = JSON.stringify({ auths: { 'registry.eve.example': { auth: 'eA==' } } });

    const config = await resolver.readImageConfig('registry.eve.example/shop/web@sha256:' + 'a'.repeat(64), { dockerConfigJson: dockerConfig });

    expect(config).toEqual({ user: '1000:1000' });
    expect(run).toHaveBeenCalledWith(['config', 'registry.eve.example/shop/web@sha256:' + 'a'.repeat(64)], expect.any(Object));
    expect(seenConfig).toBe(dockerConfig);
    expect(seenDir && fs.existsSync(seenDir)).toBe(false);
  });

  it('returns null when crane cannot read the image', async () => {
    const run = vi.fn(async () => { throw new Error('UNAUTHORIZED'); });
    const resolver = new (ImageResolver as any)(null, { warn: vi.fn(), log: vi.fn() }, run);

    await expect(resolver.readImageConfig('shop/web:1')).resolves.toBeNull();
  });
});
