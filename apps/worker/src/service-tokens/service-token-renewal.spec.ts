import { createSign, generateKeyPairSync, type KeyObject } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
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
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  environmentQueries: vi.fn(() => mocks.environments),
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
const NS = 'eve-acme-shop-prod';
const ENV = {
  id: 'env_prod',
  project_id: 'proj_shop',
  org_id: 'org_acme',
  name: 'prod',
  namespace: NS,
  release_id: 'rel_2',
  service_tokens_not_before: null as Date | null,
};
const PERMISSIONS = ['jobs:read', 'events:write'];

function serviceToken(opts: { days: number; key?: SigningKey; issuedAgo?: number; service?: string }): string {
  const service = opts.service ?? 'api';
  return sign({
    sub: `service:${service}`,
    org_id: 'org_acme',
    project_id: 'proj_shop',
    env_name: 'prod',
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

  addService(service: string, data: Record<string, string>, release = 'rel_2'): void {
    const deployment = `prod-${service}`;
    this.secrets.set(`${deployment}-eve-secrets`, {
      metadata: {
        name: `${deployment}-eve-secrets`,
        namespace: NS,
        resourceVersion: '1',
        labels: {
          [SERVICE_SECRETS_LABEL]: 'true',
          'eve.project_id': 'proj_shop',
          'eve.env_id': 'env_prod',
          'eve.component': service,
          'eve.release': release,
        },
        annotations: { [SECRET_DEPLOYMENT_ANNOTATION]: deployment },
      },
      data: Object.fromEntries(Object.entries(data).map(([k, v]) => [k, b64(v)])),
    });
    this.deployments.set(deployment, {
      metadata: { name: deployment, namespace: NS },
      spec: { template: { metadata: { annotations: { [SECRETS_HASH_ANNOTATION]: secretsHash(data) } } } },
    });
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
      Object.assign(secret.metadata.annotations, body.metadata.annotations ?? {});
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
    delete process.env.EVE_SERVICE_TOKEN_RENEW_DAYS;
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

  it('renews nothing with EVE_SERVICE_TOKEN_RENEW_DAYS=0', async () => {
    process.env.EVE_SERVICE_TOKEN_RENEW_DAYS = '0';
    const old = serviceToken({ days: 1, key: retired });
    cluster.addService('api', { EVE_SERVICE_TOKEN: old });

    await renewal.renewAll();

    expect(cluster.value('api', 'EVE_SERVICE_TOKEN')).toBe(old);
    expect(issuer.mintServiceToken).not.toHaveBeenCalled();
    expect(mocks.environments.listForServiceTokenRenewal).not.toHaveBeenCalled();
  });
});
