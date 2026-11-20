import http from 'node:http';
import type { AddressInfo } from 'node:net';
import * as k8s from '@kubernetes/client-node';
import { Logger } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { Db } from '@eve/db';
import { EnvHealthWatchdogService } from './env-health-watchdog.service.js';

// The circuit breaker scales a failing Deployment to zero through its scale
// subresource. client-node 1.x sends a patch as JSON Patch unless told
// otherwise, and the body here is a merge patch: the request must say so, or
// the API server answers 400 and the breaker never trips. The request is
// checked as it leaves the real client, against a local HTTP server.

const NS = 'eve-acme-shop-prod';

type Seen = { method: string; url: string; contentType: string; body: string };

describe('EnvHealthWatchdogService circuit breaker: the scale request', () => {
  let server: http.Server;
  let seen: Seen[];

  beforeEach(async () => {
    seen = [];
    server = http.createServer((req, res) => {
      let body = '';
      req.on('data', (chunk) => { body += chunk; });
      req.on('end', () => {
        seen.push({ method: req.method ?? '', url: req.url ?? '', contentType: String(req.headers['content-type'] ?? ''), body });
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ apiVersion: 'autoscaling/v1', kind: 'Scale', metadata: { name: 'web', namespace: NS }, spec: { replicas: 0 } }));
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()));
    // The service's own client loads the default config: never a real one here.
    vi.stubEnv('KUBECONFIG', '/dev/null');
    vi.spyOn(Logger.prototype, 'log').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'warn').mockImplementation(() => {});
    vi.spyOn(Logger.prototype, 'error').mockImplementation(() => {});
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  function serviceAgainstServer(): EnvHealthWatchdogService {
    const kc = new k8s.KubeConfig();
    kc.loadFromOptions({
      clusters: [{ name: 'local', server: `http://127.0.0.1:${(server.address() as AddressInfo).port}`, skipTLSVerify: true }],
      users: [{ name: 'local', token: 'token' }],
      contexts: [{ name: 'local', cluster: 'local', user: 'local' }],
      currentContext: 'local',
    });
    const appsApi = kc.makeApiClient(k8s.AppsV1Api);
    // Only the scale goes to the server; the reads that find the Deployment are stubbed.
    Object.assign(appsApi, {
      listNamespacedReplicaSet: vi.fn(async () => ({
        items: [{ metadata: { name: 'web-rs', ownerReferences: [{ kind: 'Deployment', name: 'web' }] } }],
      })),
      listNamespacedDeployment: vi.fn(async () => ({ items: [{ metadata: { name: 'web' } }] })),
    });
    const db = Object.assign(() => Promise.resolve([]), { json: vi.fn(), end: vi.fn() }) as unknown as Db;
    const service = new EnvHealthWatchdogService(db);
    Object.assign(service, {
      appsApi,
      coreApi: {
        listNamespacedPod: vi.fn(async () => ({
          items: [{ metadata: { name: 'web-pod', ownerReferences: [{ kind: 'ReplicaSet', name: 'web-rs' }] } }],
        })),
      },
      healthChecks: { findByEnvironmentId: vi.fn(async () => ({ degraded_since: new Date(Date.now() - 2 * 60 * 60 * 1000) })) },
      environments: { update: vi.fn(async () => ({})) },
    });
    return service;
  }

  it('sends a merge patch of the replicas to the scale subresource', async () => {
    const service = serviceAgainstServer();
    const actions = await (service as any).applyCircuitBreaker(
      { id: 'env_prod', namespace: NS },
      { status: 'critical', issues: [{ type: 'image_pull_backoff', pod: 'web-pod', container: 'web' }], podCount: 1, healthyPodCount: 0 },
    );

    expect(seen).toEqual([{
      method: 'PATCH',
      url: `/apis/apps/v1/namespaces/${NS}/deployments/web/scale`,
      contentType: 'application/merge-patch+json',
      body: JSON.stringify({ spec: { replicas: 0 } }),
    }]);
    expect(actions).toEqual([expect.objectContaining({ type: 'scale_to_zero', deployment: 'web' })]);
  });
});
