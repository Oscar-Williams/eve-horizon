import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { Logger } from '@nestjs/common';
import type { Db } from '@eve/db';
import { K8sService } from '../deployer/k8s.service.js';
import {
  SECRETS_HASH_ANNOTATION,
  SECRET_DEPLOYMENT_ANNOTATION,
  SERVICE_SECRETS_LABEL,
  secretsHash,
} from '../deployer/workload-secrets.js';
import { ServiceTokenRenewalService, type ServiceTokenIssuer } from './service-token-renewal.service.js';

/**
 * A deployed service's Eve token is renewed before it lapses: when it expires
 * within EVE_SERVICE_TOKEN_RENEW_DAYS (default 30), was signed by a key the
 * API no longer signs with, or was issued before its environment's
 * service_tokens_not_before. The worker writes only that key of the service's
 * Secret, on the Secret's resourceVersion, then changes the pod template's
 * hash so the Deployment rolls once. App-link tokens injected into services
 * follow the same rules.
 */

const mocks = vi.hoisted(() => ({
  environments: { listForServiceTokenRenewal: vi.fn() },
  events: { create: vi.fn(async (event: Record<string, unknown>) => event) },
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  environmentQueries: vi.fn(() => mocks.environments),
  eventQueries: vi.fn(() => mocks.events),
}));

interface SigningKey { kid: string; privateKey: KeyObject; publicKey: KeyObject }

function keyPair(kid: string): SigningKey {
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return { kid, privateKey, publicKey };
}

const current = keyPair('key-2');
const retired = keyPair('key-1');

function sign(payload: Record<string, unknown>, key: SigningKey): string {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ alg: 'RS256', typ: 'JWT', kid: key.kid })}.${encode(payload)}`;
  const signer = createSign('RSA-SHA256');
  signer.update(input);
  return `${input}.${signer.sign(key.privateKey).toString('base64url')}`;
}

function claims(token: string): Record<string, any> {
  return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString());
}

const NOW = Date.UTC(2026, 10, 20, 12, 0, 0);
const nowS = NOW / 1000;
const DAY = 24 * 60 * 60;
const HOUR_MS = 60 * 60 * 1000;
const FAILED = 'eve.tokens-renew-failed';
const NS = 'eve-acme-shop-prod';
const ENV = {
  id: 'env_prod',
  project_id: 'proj_shop',
  org_id: 'org_acme',
  name: 'prod',
  namespace: NS,
  release_id: 'rel_2',
  current_release_id: 'rel_2' as string | null,
  created_at: new Date(Date.UTC(2026, 0, 1)),
  service_tokens_not_before: null as Date | null,
};
const STAGING_NS = 'eve-acme-shop-staging';
const STAGING = { ...ENV, id: 'env_staging', name: 'staging', namespace: STAGING_NS };
const PERMISSIONS = ['jobs:read', 'events:write'];

function serviceToken(opts: { days: number; key?: SigningKey; issuedAgo?: number; service?: string; env?: string }): string {
  const service = opts.service ?? 'api';
  return sign({
    sub: `service:${service}`,
    org_id: 'org_acme',
    project_id: 'proj_shop',
    env_name: opts.env ?? 'prod',
    service_name: service,
    permissions: PERMISSIONS,
    iat: nowS - (opts.issuedAgo ?? 60 * DAY),
    exp: nowS + opts.days * DAY,
    type: 'service',
  }, opts.key ?? current);
}

function appLinkToken(opts: { days: number; key?: SigningKey }): string {
  return sign({
    sub: 'app_link:sub_ledger',
    subscription_id: 'sub_ledger',
    consumer_project_id: 'proj_shop',
    consumer_org_id: 'org_acme',
    consumer_principal: 'service:api',
    consumer_env: 'prod',
    producer_project_id: 'proj_ledger',
    producer_env: 'prod',
    api_name: 'ledger',
    scopes: ['ledger:read'],
    aud: 'project:proj_ledger',
    iat: nowS - 60 * DAY,
    exp: nowS + opts.days * DAY,
    type: 'app_link',
  }, opts.key ?? current);
}

function k8sError(statusCode: number): Error {
  return Object.assign(new Error(`HTTP ${statusCode}`), { statusCode, response: { statusCode } });
}

const b64 = (value: string) => Buffer.from(value, 'utf8').toString('base64');
const unb64 = (value: string) => Buffer.from(value, 'base64').toString('utf8');

/** Service Secrets and Deployments of one namespace, behind the k8s client calls the worker makes. */
class Cluster {
  readonly secrets = new Map<string, any>();
  readonly deployments = new Map<string, any>();
  /** Runs after a Secret is read: a write that lands before the renewal's patch. */
  afterRead?: (name: string) => void;

  addService(
    service: string,
    data: Record<string, string>,
    release = 'rel_2',
    options: { strategy?: 'Recreate' | 'RollingUpdate'; env?: typeof ENV } = {},
  ): void {
    const env = options.env ?? ENV;
    const deployment = `${env.name}-${service}`;
    this.secrets.set(`${deployment}-eve-secrets`, {
      metadata: {
        name: `${deployment}-eve-secrets`,
        namespace: env.namespace,
        resourceVersion: '1',
        labels: {
          [SERVICE_SECRETS_LABEL]: 'true',
          'eve.project_id': 'proj_shop',
          'eve.env_id': env.id,
          'eve.component': service,
          'eve.release': release,
        },
        annotations: { [SECRET_DEPLOYMENT_ANNOTATION]: deployment },
      },
      data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, b64(v)])),
    });
    this.deployments.set(deployment, {
      metadata: { name: deployment, namespace: env.namespace, generation: 1 },
      spec: {
        replicas: 1,
        strategy: { type: options.strategy ?? 'RollingUpdate' },
        template: { metadata: { annotations: { [SECRETS_HASH_ANNOTATION]: secretsHash(data) } } },
      },
      status: { observedGeneration: 1, replicas: 1, updatedReplicas: 1, availableReplicas: 1 },
    });
  }

  /** The new pods of a Deployment's latest roll serve, and the old ones are gone. */
  finishRollout(deployment: string): void {
    const d = this.deployments.get(deployment);
    d.status = { observedGeneration: d.metadata.generation, replicas: 1, updatedReplicas: 1, availableReplicas: 1 };
  }

  secretValue(deployment: string, key: string): string {
    return unb64(this.secrets.get(`${deployment}-eve-secrets`).data[key]);
  }

  templateHash(deployment: string): string {
    return this.deployments.get(deployment).spec.template.metadata.annotations[SECRETS_HASH_ANNOTATION];
  }

  secretData(deployment: string): Record<string, string> {
    const data = this.secrets.get(`${deployment}-eve-secrets`).data as Record<string, string>;
    return Object.fromEntries(Object.entries(data).map(([k, v]) => [k, unb64(v)]));
  }

  value(service: string, key: string): string {
    return unb64(this.secrets.get(`prod-${service}-eve-secrets`).data[key]);
  }

  hash(service: string): string {
    return this.deployments.get(`prod-${service}`).spec.template.metadata.annotations[SECRETS_HASH_ANNOTATION];
  }

  /** Overwrite a Secret as a deploy would. */
  write(name: string, data: Record<string, string>): void {
    const secret = this.secrets.get(name);
    for (const [k, v] of Object.entries(data)) secret.data[k] = b64(v);
    secret.metadata.resourceVersion = String(Number(secret.metadata.resourceVersion) + 1);
  }

  coreApi = {
    listNamespacedSecret: vi.fn(async (_ns: string, _p?: unknown, _a?: unknown, _c?: unknown, _f?: unknown, selector?: string) => {
      const wanted = (selector ?? '').split(',').filter(Boolean).map((pair) => pair.split('='));
      const items = [...this.secrets.values()]
        .filter((s) => wanted.every(([k, v]) => s.metadata.labels[k] === v))
        .map((s) => structuredClone(s));
      return { body: { items } };
    }),
    readNamespacedSecret: vi.fn(async (name: string) => {
      const secret = this.secrets.get(name);
      if (!secret) throw k8sError(404);
      const copy = structuredClone(secret);
      this.afterRead?.(name);
      return { body: copy };
    }),
    patchNamespacedSecret: vi.fn(async (name: string, _ns: string, body: any) => {
      const secret = this.secrets.get(name);
      if (!secret) throw k8sError(404);
      if (body.metadata?.resourceVersion !== secret.metadata.resourceVersion) throw k8sError(409);
      Object.assign(secret.data, body.data);
      for (const [key, value] of Object.entries(body.metadata.annotations ?? {})) {
        if (value === null) delete secret.metadata.annotations[key];
        else secret.metadata.annotations[key] = value;
      }
      secret.metadata.resourceVersion = String(Number(secret.metadata.resourceVersion) + 1);
      return { body: secret };
    }),
  };

  appsApi = {
    readNamespacedDeployment: vi.fn(async (name: string) => {
      const deployment = this.deployments.get(name);
      if (!deployment) throw k8sError(404);
      return { body: structuredClone(deployment) };
    }),
    patchNamespacedDeployment: vi.fn(async (name: string, _ns: string, body: any) => {
      const deployment = this.deployments.get(name);
      if (!deployment) throw k8sError(404);
      Object.assign(deployment.spec.template.metadata.annotations, body.spec.template.metadata.annotations);
      // The roll starts: a surge pod runs the new template, the old one still serves.
      deployment.metadata.generation += 1;
      deployment.status = { observedGeneration: deployment.metadata.generation, replicas: 2, updatedReplicas: 1, availableReplicas: 1 };
      return { body: deployment };
    }),
  };
}

function issuerFor(): ServiceTokenIssuer & Record<string, ReturnType<typeof vi.fn>> {
  return {
    signingKey: vi.fn(async () => ({ kid: current.kid, publicKey: current.publicKey })),
    mintServiceToken: vi.fn(async (p: any) => sign({
      sub: `service:${p.serviceName}`,
      org_id: p.orgId,
      project_id: p.projectId,
      env_name: p.envName,
      service_name: p.serviceName,
      permissions: p.permissions,
      iat: nowS,
      exp: nowS + 90 * DAY,
      type: 'service',
    }, current)),
    mintAppLinkToken: vi.fn(async (p: any) => sign({
      sub: `app_link:${p.subscriptionId}`,
      subscription_id: p.subscriptionId,
      consumer_project_id: p.consumerProjectId,
      consumer_principal: p.consumerPrincipal,
      consumer_env: p.consumerEnv,
      producer_env: p.producerEnv,
      iat: nowS,
      exp: nowS + 90 * DAY,
      type: 'app_link',
    }, current)),
  } as any;
}

describe('service token renewal', () => {
  let cluster: Cluster;
  let issuer: ReturnType<typeof issuerFor>;
  let renewal: ServiceTokenRenewalService;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    delete process.env.EVE_SERVICE_TOKEN_RENEW_DAYS;
    mocks.environments.listForServiceTokenRenewal.mockResolvedValue([ENV]);
    cluster = new Cluster();
    const k8s = new K8sService();
    Object.assign(k8s as any, { coreApi: cluster.coreApi, appsApi: cluster.appsApi, available: true });
    issuer = issuerFor();
    renewal = new ServiceTokenRenewalService({} as Db, k8s, issuer);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    delete process.env.EVE_SERVICE_TOKEN_RENEW_DAYS;
    delete process.env.EVE_SERVICE_TOKEN_RENEW_BATCH;
  });

  it('renews a token that expires in 20 days, with the same permissions, and rolls the pods', async () => {
    const old = serviceToken({ days: 20 });
    cluster.addService('api', { EVE_SERVICE_TOKEN: old, DATABASE_URL: 'postgres://shop' });
    const hashBefore = cluster.hash('api');

    await renewal.renewAll();

    const renewed = cluster.value('api', 'EVE_SERVICE_TOKEN');
    expect(renewed).not.toBe(old);
    expect(claims(renewed)).toMatchObject({ service_name: 'api', permissions: PERMISSIONS, exp: nowS + 90 * DAY });
    expect(issuer.mintServiceToken).toHaveBeenCalledWith(expect.objectContaining({
      projectId: 'proj_shop',
      orgId: 'org_acme',
      envName: 'prod',
      serviceName: 'api',
      permissions: PERMISSIONS,
      releaseId: 'rel_2',
    }));
    // Only that key was written, on the Secret's resourceVersion.
    expect(cluster.coreApi.patchNamespacedSecret).toHaveBeenCalledWith(
      'prod-api-eve-secrets',
      NS,
      { metadata: expect.objectContaining({ resourceVersion: '1' }), data: { EVE_SERVICE_TOKEN: b64(renewed) } },
      undefined, undefined, undefined, undefined, undefined,
      expect.objectContaining({ headers: { 'Content-Type': 'application/merge-patch+json' } }),
    );
    expect(cluster.value('api', 'DATABASE_URL')).toBe('postgres://shop');
    expect(cluster.hash('api')).not.toBe(hashBefore);
    expect(cluster.hash('api')).toBe(secretsHash({ EVE_SERVICE_TOKEN: renewed, DATABASE_URL: 'postgres://shop' }));
    expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(1);
  });

  it('leaves one with 40 days left alone', async () => {
    const token = serviceToken({ days: 40 });
    cluster.addService('api', { EVE_SERVICE_TOKEN: token });
    const hashBefore = cluster.hash('api');

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).toBe(token);
    expect(cluster.hash('api')).toBe(hashBefore);
    expect(issuer.mintServiceToken).not.toHaveBeenCalled();
    expect(cluster.coreApi.patchNamespacedSecret).not.toHaveBeenCalled();
    expect(cluster.appsApi.patchNamespacedDeployment).not.toHaveBeenCalled();
  });

  it('renews one signed by a retired key', async () => {
    const old = serviceToken({ days: 80, key: retired });
    cluster.addService('api', { EVE_SERVICE_TOKEN: old });

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(old);
    expect(issuer.mintServiceToken).toHaveBeenCalledTimes(1);
  });

  it('renews one whose kid is current but whose signature is not the current key\'s', async () => {
    const old = serviceToken({ days: 80, key: { ...retired, kid: current.kid } });
    cluster.addService('api', { EVE_SERVICE_TOKEN: old });

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(old);
  });

  it('renews one issued before the environment\'s service_tokens_not_before', async () => {
    mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
      { ...ENV, service_tokens_not_before: new Date(NOW - 60_000) },
    ]);
    const old = serviceToken({ days: 80, issuedAgo: 120 });
    const fresh = serviceToken({ days: 80, issuedAgo: 30, service: 'web' });
    cluster.addService('api', { EVE_SERVICE_TOKEN: old });
    cluster.addService('web', { EVE_SERVICE_TOKEN: fresh });

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(old);
    expect(cluster.value('web', 'EVE_SERVICE_TOKEN')).toBe(fresh);
  });

  it('renews one issued before its environment was created, which the API refuses', async () => {
    mocks.environments.listForServiceTokenRenewal.mockResolvedValue([{ ...ENV, created_at: new Date(NOW - 60_000) }]);
    const old = serviceToken({ days: 80, issuedAgo: 120 });
    cluster.addService('api', { EVE_SERVICE_TOKEN: old });

    const report = await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(old);
    expect(report.renewed).toEqual([expect.objectContaining({ key: 'EVE_SERVICE_TOKEN', reason: 'revoked' })]);
  });

  it('skips a service whose environment sets EVE_SERVICE_TOKEN', async () => {
    // The manifest blanks it (`EVE_SERVICE_TOKEN: ""`); the deployer wrote that value.
    cluster.addService('portal', { EVE_SERVICE_TOKEN: '', SESSION_SECRET: 's3cret' });
    const hashBefore = cluster.hash('portal');

    await renewal.renewAll();

    expect(cluster.value('portal', 'EVE_SERVICE_TOKEN')).toBe('');
    expect(cluster.hash('portal')).toBe(hashBefore);
    expect(issuer.mintServiceToken).not.toHaveBeenCalled();
    expect(cluster.appsApi.patchNamespacedDeployment).not.toHaveBeenCalled();
  });

  it('renews an injected app-link token by the same rules', async () => {
    const service = serviceToken({ days: 40 });
    const link = appLinkToken({ days: 20 });
    cluster.addService('api', { EVE_SERVICE_TOKEN: service, EVE_APP_LINK_LEDGER_TOKEN: link });
    const hashBefore = cluster.hash('api');

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).toBe(service);
    const renewed = cluster.value('api', 'EVE_APP_LINK_LEDGER_TOKEN');
    expect(renewed).not.toBe(link);
    expect(issuer.mintAppLinkToken).toHaveBeenCalledWith(expect.objectContaining({
      subscriptionId: 'sub_ledger',
      consumerPrincipal: 'service:api',
      consumerProjectId: 'proj_shop',
      consumerEnv: 'prod',
      producerEnv: 'prod',
      ttlSeconds: 90 * DAY,
    }));
    expect(cluster.hash('api')).not.toBe(hashBefore);
  });

  it('leaves an injected app-link token with 40 days left alone', async () => {
    const link = appLinkToken({ days: 40 });
    cluster.addService('api', { EVE_SERVICE_TOKEN: serviceToken({ days: 40 }), EVE_APP_LINK_LEDGER_TOKEN: link });

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_APP_LINK_LEDGER_TOKEN')).toBe(link);
    expect(issuer.mintAppLinkToken).not.toHaveBeenCalled();
  });

  it('leaves a Secret changed between read and patch alone until the next run', async () => {
    const old = serviceToken({ days: 20 });
    cluster.addService('api', { EVE_SERVICE_TOKEN: old, DATABASE_URL: 'postgres://shop' });
    const hashBefore = cluster.hash('api');
    cluster.afterRead = (name) => {
      cluster.afterRead = undefined;
      cluster.write(name, { DATABASE_URL: 'postgres://shop-v2' });
    };

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).toBe(old);
    expect(cluster.value('api', 'DATABASE_URL')).toBe('postgres://shop-v2');
    expect(cluster.hash('api')).toBe(hashBefore);
    expect(cluster.appsApi.patchNamespacedDeployment).not.toHaveBeenCalled();

    await renewal.renewAll();

    const renewed = cluster.value('api', 'EVE_SERVICE_TOKEN');
    expect(renewed).not.toBe(old);
    expect(cluster.hash('api')).toBe(secretsHash({ EVE_SERVICE_TOKEN: renewed, DATABASE_URL: 'postgres://shop-v2' }));
  });

  it('finishes a roll that failed on the next run, and rolls only once', async () => {
    cluster.addService('api', { EVE_SERVICE_TOKEN: serviceToken({ days: 20 }) });
    const hashBefore = cluster.hash('api');
    cluster.appsApi.patchNamespacedDeployment.mockRejectedValueOnce(k8sError(500));

    await renewal.renewAll();
    expect(cluster.hash('api')).toBe(hashBefore);

    vi.setSystemTime(NOW + HOUR_MS);
    await renewal.renewAll();
    const renewed = cluster.value('api', 'EVE_SERVICE_TOKEN');
    expect(cluster.hash('api')).toBe(secretsHash({ EVE_SERVICE_TOKEN: renewed }));
    expect(issuer.mintServiceToken).toHaveBeenCalledTimes(1);

    await renewal.renewAll();
    expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(2);
  });

  it('leaves the Secret of a service no longer in the applied release alone', async () => {
    const old = serviceToken({ days: 20, service: 'legacy' });
    cluster.addService('legacy', { EVE_SERVICE_TOKEN: old }, 'rel_1');

    await renewal.renewAll();

    expect(cluster.value('legacy', 'EVE_SERVICE_TOKEN')).toBe(old);
    expect(issuer.mintServiceToken).not.toHaveBeenCalled();
  });

  it('renews one environment on request (a rotation), its revoked tokens even with the hourly pass off', async () => {
    process.env.EVE_SERVICE_TOKEN_RENEW_DAYS = '0';
    mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
      { ...ENV, service_tokens_not_before: new Date(NOW) },
    ]);
    const revoked = serviceToken({ days: 80, issuedAgo: 5 });
    cluster.addService('api', { EVE_SERVICE_TOKEN: revoked });

    const report = await renewal.renewEnvironment('env_prod');

    expect(mocks.environments.listForServiceTokenRenewal).toHaveBeenCalledWith('env_prod');
    expect(report).toEqual({
      renewed: [expect.objectContaining({ env_id: 'env_prod', key: 'EVE_SERVICE_TOKEN', reason: 'revoked' })],
      conflicted: [],
      failed: [],
    });
    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(revoked);
  });

  it('reports on a rotation what it renewed, what a write in between held back, and what it could not renew', async () => {
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
    mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
      { ...ENV, service_tokens_not_before: new Date(NOW) },
    ]);
    for (const service of ['api', 'web', 'worker']) {
      cluster.addService(service, { EVE_SERVICE_TOKEN: serviceToken({ days: 80, issuedAgo: 5, service }) });
    }
    cluster.afterRead = (name) => {
      if (name === 'prod-web-eve-secrets') cluster.write(name, { DATABASE_URL: 'postgres://shop-v2' });
    };
    const mint = vi.mocked(issuer.mintServiceToken).getMockImplementation()!;
    vi.mocked(issuer.mintServiceToken).mockImplementation(async (p) => (p.serviceName === 'worker' ? null : mint(p)));

    const report = await renewal.renewEnvironment('env_prod');

    const entry = (service: string) => expect.objectContaining({
      secret: `prod-${service}-eve-secrets`, key: 'EVE_SERVICE_TOKEN', reason: 'revoked',
    });
    expect(report.renewed).toEqual([entry('api')]);
    expect(report.conflicted).toEqual([entry('web')]);
    expect(report.failed).toEqual([entry('worker')]);
  });

  it('fails a rotation whose environment cannot be read, so the API reports it to the hourly pass', async () => {
    mocks.environments.listForServiceTokenRenewal.mockResolvedValue([{ ...ENV, service_tokens_not_before: new Date(NOW) }]);
    cluster.coreApi.listNamespacedSecret.mockRejectedValueOnce(k8sError(500));

    await expect(renewal.renewEnvironment('env_prod')).rejects.toThrow();
  });

  it('renews nothing with EVE_SERVICE_TOKEN_RENEW_DAYS=0', async () => {
    process.env.EVE_SERVICE_TOKEN_RENEW_DAYS = '0';
    const old = serviceToken({ days: 1, key: retired });
    cluster.addService('api', { EVE_SERVICE_TOKEN: old });

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).toBe(old);
    expect(issuer.mintServiceToken).not.toHaveBeenCalled();
    expect(mocks.environments.listForServiceTokenRenewal).not.toHaveBeenCalled();
  });

  describe('unattended rolls', () => {
    const logs = () => [
      ...vi.mocked(Logger.prototype.log).mock.calls,
      ...vi.mocked(Logger.prototype.warn).mock.calls,
    ].map((call) => String(call[0])).join('\n');

    beforeEach(() => {
      vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
      vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
      vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    });

    it('renews and rolls at most three Deployments a pass, the soonest to expire first', async () => {
      const days: Record<string, number> = { a: 25, b: 5, c: 20, d: 10, e: 15 };
      const tokens: Record<string, string> = {};
      for (const [service, left] of Object.entries(days)) {
        tokens[service] = serviceToken({ days: left, service });
        cluster.addService(service, { EVE_SERVICE_TOKEN: tokens[service] });
      }

      await renewal.renewAll();

      const renewed = () => Object.keys(days).filter((service) => cluster.value(service, 'EVE_SERVICE_TOKEN') !== tokens[service]);
      expect(renewed()).toEqual(['b', 'd', 'e']);
      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(3);
      expect(issuer.mintServiceToken).toHaveBeenCalledTimes(3);

      await renewal.renewAll();

      expect(renewed()).toEqual(['a', 'b', 'c', 'd', 'e']);
      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(5);
    });

    it('takes the batch from EVE_SERVICE_TOKEN_RENEW_BATCH, the soonest to expire first across environments', async () => {
      process.env.EVE_SERVICE_TOKEN_RENEW_BATCH = '1';
      mocks.environments.listForServiceTokenRenewal.mockResolvedValue([ENV, STAGING]);
      const prod = serviceToken({ days: 20 });
      const staging = serviceToken({ days: 5, service: 'web', env: 'staging' });
      cluster.addService('api', { EVE_SERVICE_TOKEN: prod });
      cluster.addService('web', { EVE_SERVICE_TOKEN: staging }, 'rel_2', { env: STAGING });

      await renewal.renewAll();

      expect(cluster.secretValue('staging-web', 'EVE_SERVICE_TOKEN')).not.toBe(staging);
      expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).toBe(prod);
      expect(issuer.mintServiceToken).toHaveBeenCalledTimes(1);
    });

    it('writes a Recreate service\'s renewed Secret but does not roll it while its token has more than 7 days left, and says so', async () => {
      const old = serviceToken({ days: 20, service: 'db' });
      cluster.addService('db', { EVE_SERVICE_TOKEN: old }, 'rel_2', { strategy: 'Recreate' });
      const hashBefore = cluster.templateHash('prod-db');

      await renewal.renewAll();

      expect(cluster.value('db', 'EVE_SERVICE_TOKEN')).not.toBe(old);
      expect(cluster.templateHash('prod-db')).toBe(hashBefore);
      expect(cluster.appsApi.patchNamespacedDeployment).not.toHaveBeenCalled();
      expect(logs()).toMatch(/prod-db.*Recreate/);
    });

    it('rolls that Recreate service once the token its pods hold is within 7 days of expiry', async () => {
      cluster.addService('db', { EVE_SERVICE_TOKEN: serviceToken({ days: 20, service: 'db' }) }, 'rel_2', { strategy: 'Recreate' });
      await renewal.renewAll();
      expect(cluster.appsApi.patchNamespacedDeployment).not.toHaveBeenCalled();

      vi.setSystemTime(NOW + 10 * DAY * 1000);
      await renewal.renewAll();
      expect(cluster.appsApi.patchNamespacedDeployment).not.toHaveBeenCalled();

      vi.setSystemTime(NOW + 14 * DAY * 1000);
      await renewal.renewAll();

      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(1);
      expect(cluster.templateHash('prod-db')).toBe(secretsHash(cluster.secretData('prod-db')));
      expect(issuer.mintServiceToken).toHaveBeenCalledTimes(1);
    });

    it('rolls a Recreate service at once when its token expires within 7 days', async () => {
      cluster.addService('db', { EVE_SERVICE_TOKEN: serviceToken({ days: 5, service: 'db' }) }, 'rel_2', { strategy: 'Recreate' });

      await renewal.renewAll();

      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(1);
      expect(cluster.templateHash('prod-db')).toBe(secretsHash(cluster.secretData('prod-db')));
    });

    it('rolls a Recreate service at once when its token is revoked', async () => {
      mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
        { ...ENV, service_tokens_not_before: new Date(NOW - 60_000) },
      ]);
      cluster.addService('db', { EVE_SERVICE_TOKEN: serviceToken({ days: 80, issuedAgo: 120, service: 'db' }) }, 'rel_2', { strategy: 'Recreate' });

      await renewal.renewAll();

      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(1);
    });

    it('rolls Recreate services at once when their revoked tokens also expire within 30 days or were signed by a retired key', async () => {
      mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
        { ...ENV, service_tokens_not_before: new Date(NOW - 60_000) },
      ]);
      cluster.addService('db', { EVE_SERVICE_TOKEN: serviceToken({ days: 25, issuedAgo: 65, service: 'db' }) }, 'rel_2', { strategy: 'Recreate' });
      cluster.addService('cache', { EVE_SERVICE_TOKEN: serviceToken({ days: 80, issuedAgo: 120, key: retired, service: 'cache' }) }, 'rel_2', { strategy: 'Recreate' });

      const report = await renewal.renewAll();

      expect(report.renewed).toEqual(expect.arrayContaining([
        expect.objectContaining({ secret: 'prod-db-eve-secrets', reason: 'revoked' }),
        expect.objectContaining({ secret: 'prod-cache-eve-secrets', reason: 'revoked' }),
      ]));
      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(2);
      expect(cluster.templateHash('prod-db')).toBe(secretsHash(cluster.secretData('prod-db')));
      expect(cluster.templateHash('prod-cache')).toBe(secretsHash(cluster.secretData('prod-cache')));
    });

    it('takes a revoked token that also expires within 30 days before one closer to expiry', async () => {
      process.env.EVE_SERVICE_TOKEN_RENEW_BATCH = '1';
      mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
        { ...ENV, service_tokens_not_before: new Date(NOW - 60_000) },
        STAGING,
      ]);
      const revoked = serviceToken({ days: 25, issuedAgo: 65 });
      const staging = serviceToken({ days: 5, service: 'web', env: 'staging' });
      cluster.addService('api', { EVE_SERVICE_TOKEN: revoked });
      cluster.addService('web', { EVE_SERVICE_TOKEN: staging }, 'rel_2', { env: STAGING });

      await renewal.renewAll();

      expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(revoked);
      expect(cluster.secretValue('staging-web', 'EVE_SERVICE_TOKEN')).toBe(staging);
    });

    it('rolls a deferred Recreate service at once when its pods\' token is revoked later', async () => {
      cluster.addService('db', { EVE_SERVICE_TOKEN: serviceToken({ days: 20, service: 'db' }) }, 'rel_2', { strategy: 'Recreate' });
      await renewal.renewAll();
      expect(cluster.appsApi.patchNamespacedDeployment).not.toHaveBeenCalled();

      vi.setSystemTime(NOW + 60_000);
      mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
        { ...ENV, service_tokens_not_before: new Date(NOW + 60_000) },
      ]);
      await renewal.renewAll();

      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(1);
      expect(cluster.templateHash('prod-db')).toBe(secretsHash(cluster.secretData('prod-db')));
    });

    describe('Secrets that fail', () => {
      const failure = (deployment: string) => {
        const raw = cluster.secrets.get(`${deployment}-eve-secrets`).metadata.annotations[FAILED];
        return raw === undefined ? null : JSON.parse(raw);
      };
      const hoursLater = (hours: number) => vi.setSystemTime(NOW + hours * HOUR_MS);

      it('do not take the batch: three that fail every pass leave room for a fourth environment', async () => {
        mocks.environments.listForServiceTokenRenewal.mockResolvedValue([ENV, STAGING]);
        // A revoked app-link grant, a release that is gone, and an admission refusal of the roll.
        const link = appLinkToken({ days: 2 });
        cluster.addService('api', { EVE_SERVICE_TOKEN: serviceToken({ days: 40 }), EVE_APP_LINK_LEDGER_TOKEN: link });
        cluster.addService('worker', { EVE_SERVICE_TOKEN: serviceToken({ days: 3, service: 'worker' }) });
        cluster.addService('web', { EVE_SERVICE_TOKEN: serviceToken({ days: 4, service: 'web' }) });
        const staging = serviceToken({ days: 20, service: 'web', env: 'staging' });
        cluster.addService('web', { EVE_SERVICE_TOKEN: staging }, 'rel_2', { env: STAGING });
        vi.mocked(issuer.mintAppLinkToken).mockResolvedValue(null);
        const mint = vi.mocked(issuer.mintServiceToken).getMockImplementation()!;
        vi.mocked(issuer.mintServiceToken).mockImplementation(async (p) => (p.serviceName === 'worker' ? { status: 404 } : mint(p)));
        const roll = cluster.appsApi.patchNamespacedDeployment.getMockImplementation()!;
        cluster.appsApi.patchNamespacedDeployment.mockImplementation(async (name: string, ns: string, body: any) => {
          if (name === 'prod-web') throw k8sError(403);
          return roll(name, ns, body);
        });

        const report = await renewal.renewAll();

        expect(cluster.secretValue('staging-web', 'EVE_SERVICE_TOKEN')).not.toBe(staging);
        expect(cluster.templateHash('staging-web')).toBe(secretsHash(cluster.secretData('staging-web')));
        expect(report.renewed).toEqual([expect.objectContaining({ env_id: 'env_staging', secret: 'staging-web-eve-secrets' })]);
        expect(report.failed.map((item) => item.secret).sort()).toEqual(
          ['prod-api-eve-secrets', 'prod-web-eve-secrets', 'prod-worker-eve-secrets'],
        );
        for (const deployment of ['prod-api', 'prod-worker', 'prod-web']) {
          const recorded = failure(deployment);
          expect(recorded).toMatchObject({ at: new Date(NOW).toISOString(), failures: 1, reason: expect.any(String) });
          expect(recorded.reason.length).toBeLessThanOrEqual(200);
          // No token in the record.
          expect(recorded.reason).not.toMatch(/eyJ/);
          expect(logs()).toMatch(new RegExp(`${deployment}-eve-secrets.*failed`));
        }
        expect(failure('staging-web')).toBeNull();
      });

      it('are tried again an hour after they fail, then after 2 hours, and the record goes once they renew', async () => {
        const old = serviceToken({ days: 5 });
        cluster.addService('api', { EVE_SERVICE_TOKEN: old });
        let refuse = true;
        const mint = vi.mocked(issuer.mintServiceToken).getMockImplementation()!;
        vi.mocked(issuer.mintServiceToken).mockImplementation(async (p) => (refuse ? null : mint(p)));

        await renewal.renewAll();
        expect(failure('prod-api')).toMatchObject({ at: new Date(NOW).toISOString(), failures: 1 });

        hoursLater(0.5);
        await renewal.renewAll();
        expect(issuer.mintServiceToken).toHaveBeenCalledTimes(1);

        hoursLater(1);
        await renewal.renewAll();
        expect(issuer.mintServiceToken).toHaveBeenCalledTimes(2);
        expect(failure('prod-api')).toMatchObject({ at: new Date(NOW + HOUR_MS).toISOString(), failures: 2 });

        hoursLater(2);
        await renewal.renewAll();
        expect(issuer.mintServiceToken).toHaveBeenCalledTimes(2);

        refuse = false;
        hoursLater(3);
        await renewal.renewAll();
        expect(issuer.mintServiceToken).toHaveBeenCalledTimes(3);
        expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(old);
        expect(failure('prod-api')).toBeNull();
      });

      it('wait at most a day between tries', async () => {
        cluster.addService('api', { EVE_SERVICE_TOKEN: serviceToken({ days: 5 }) });
        const secret = cluster.secrets.get('prod-api-eve-secrets');
        secret.metadata.annotations[FAILED] = JSON.stringify({
          at: new Date(NOW - 23 * HOUR_MS).toISOString(), failures: 9, reason: 'the API minted no token',
        });

        await renewal.renewAll();
        expect(issuer.mintServiceToken).not.toHaveBeenCalled();

        hoursLater(1);
        await renewal.renewAll();
        expect(issuer.mintServiceToken).toHaveBeenCalledTimes(1);
        expect(failure('prod-api')).toBeNull();
      });

      it('are tried at once on a rotation', async () => {
        mocks.environments.listForServiceTokenRenewal.mockResolvedValue([{ ...ENV, service_tokens_not_before: new Date(NOW) }]);
        const revoked = serviceToken({ days: 80, issuedAgo: 5 });
        cluster.addService('api', { EVE_SERVICE_TOKEN: revoked });
        cluster.secrets.get('prod-api-eve-secrets').metadata.annotations[FAILED] = JSON.stringify({
          at: new Date(NOW).toISOString(), failures: 1, reason: 'the API minted no token',
        });

        const report = await renewal.renewEnvironment('env_prod');

        expect(report.renewed).toEqual([expect.objectContaining({ secret: 'prod-api-eve-secrets', reason: 'revoked' })]);
        expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(revoked);
      });
    });

    it('warns, and records an event, when a roll has not finished by the next pass past the deploy timeout', async () => {
      cluster.addService('api', { EVE_SERVICE_TOKEN: serviceToken({ days: 20 }) });
      await renewal.renewAll();
      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(1);

      vi.setSystemTime(NOW + 60 * 60 * 1000);
      await renewal.renewAll();

      expect(vi.mocked(Logger.prototype.warn).mock.calls.map((c) => String(c[0])).join('\n')).toMatch(/prod-api.*not finished/);
      expect(mocks.events.create).toHaveBeenCalledWith(expect.objectContaining({
        project_id: 'proj_shop',
        env_name: 'prod',
        type: 'system.service_token.rollout_stuck',
        payload_json: expect.objectContaining({ env_id: 'env_prod', namespace: NS, deployment: 'prod-api' }),
      }));
    });

    it('says nothing more once the roll has finished', async () => {
      cluster.addService('api', { EVE_SERVICE_TOKEN: serviceToken({ days: 20 }) });
      await renewal.renewAll();
      cluster.finishRollout('prod-api');

      vi.setSystemTime(NOW + 60 * 60 * 1000);
      await renewal.renewAll();

      expect(vi.mocked(Logger.prototype.warn).mock.calls.map((c) => String(c[0])).join('\n')).not.toMatch(/not finished/);
      expect(mocks.events.create).not.toHaveBeenCalled();
    });

    it('renews and rolls every service of the environment on a rotation, past the batch', async () => {
      mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
        { ...ENV, service_tokens_not_before: new Date(NOW) },
      ]);
      const services = ['a', 'b', 'c', 'd', 'e'];
      for (const service of services) {
        cluster.addService(service, { EVE_SERVICE_TOKEN: serviceToken({ days: 80, issuedAgo: 5, service }) });
      }

      await renewal.renewEnvironment('env_prod');

      expect(issuer.mintServiceToken).toHaveBeenCalledTimes(5);
      expect(cluster.appsApi.patchNamespacedDeployment).toHaveBeenCalledTimes(5);
    });
  });

  describe('a release that is gone', () => {
    beforeEach(() => {
      vi.spyOn(Logger.prototype, 'log').mockImplementation(() => undefined);
      vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => undefined);
      vi.spyOn(Logger.prototype, 'error').mockImplementation(() => undefined);
    });

    const errors = () => vi.mocked(Logger.prototype.error).mock.calls.map((call) => String(call[0])).join('\n');

    it('falls back to the environment\'s current release when the applied one is not found, and says so', async () => {
      mocks.environments.listForServiceTokenRenewal.mockResolvedValue([
        { ...ENV, release_id: 'rel_3', current_release_id: 'rel_2' },
      ]);
      const mintService = vi.mocked(issuer.mintServiceToken);
      const mint = mintService.getMockImplementation()!;
      mintService.mockImplementation(async (p) => (p.releaseId === 'rel_3' ? { status: 404 } : mint(p)));
      const old = serviceToken({ days: 20 });
      cluster.addService('api', { EVE_SERVICE_TOKEN: old }, 'rel_3');

      await renewal.renewAll();

      expect(mintService.mock.calls.map(([p]) => p.releaseId)).toEqual(['rel_3', 'rel_2']);
      expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).not.toBe(old);
      expect(errors()).toMatch(/prod.*env_prod.*rel_3.*rel_2/);
    });

    it('renews nothing, and says so, when the release not found is also the current one', async () => {
      vi.mocked(issuer.mintServiceToken).mockResolvedValue({ status: 404 });
      const old = serviceToken({ days: 20 });
      cluster.addService('api', { EVE_SERVICE_TOKEN: old });

      await renewal.renewAll();

      expect(issuer.mintServiceToken).toHaveBeenCalledTimes(1);
      expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).toBe(old);
      // No token is written (a failure may be recorded on the Secret).
      for (const [, , body] of cluster.coreApi.patchNamespacedSecret.mock.calls) {
        expect(body.data ?? {}).toEqual({});
      }
      expect(errors()).toMatch(/prod.*env_prod.*rel_2/);
    });
  });
});
