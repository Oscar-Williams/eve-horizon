import { describe, expect, it, vi } from 'vitest';
import { EnvDiagnosticsService } from './env-diagnostics.service';

/**
 * Env health (and so the CLI's deploy watch) and env diagnose count a
 * Deployment ready only once its new pods serve, as the worker does: an old
 * pod that is still available right after an apply does not count.
 */
function diagnosticsWith(items: unknown[]): EnvDiagnosticsService {
  const diagnostics = Object.create(EnvDiagnosticsService.prototype) as EnvDiagnosticsService;
  Object.assign(diagnostics as any, {
    k8sAvailable: true,
    appsApi: { listNamespacedDeployment: vi.fn(async () => ({ items })) },
    coreApi: {
      listNamespacedPod: vi.fn(async () => ({ items: [] })),
      listNamespacedEvent: vi.fn(async () => ({ items: [] })),
    },
    listStorageBuckets: vi.fn(async () => []),
    listHttpIngress: vi.fn(async () => []),
    listTcpIngress: vi.fn(async () => []),
  });
  return diagnostics;
}

const rolled = {
  metadata: { name: 'prod-web', generation: 2 },
  spec: { replicas: 1 },
  status: { observedGeneration: 2, replicas: 1, updatedReplicas: 1, availableReplicas: 1 },
};
// One desired: the old pod is still available, the new one is not.
const rolling = {
  metadata: { name: 'prod-api', generation: 2 },
  spec: { replicas: 1 },
  status: { observedGeneration: 2, replicas: 2, updatedReplicas: 1, availableReplicas: 2 },
};

describe('env health waits for the new pods', () => {
  it('is not ready while a Deployment still rolls, though its old pod is available', async () => {
    const health = await diagnosticsWith([rolled, rolling]).getHealth('proj_shop', 'prod', 'eve-acme-shop-prod');

    expect(health.ready).toBe(false);
    expect(health.status).toBe('deploying');
    expect(health.warnings?.join(' ')).toContain('prod-api');
  });

  it('is ready once every Deployment has rolled', async () => {
    const health = await diagnosticsWith([rolled]).getHealth('proj_shop', 'prod', 'eve-acme-shop-prod');

    expect(health.ready).toBe(true);
    expect(health.status).toBe('ready');
  });

  it('env diagnose marks the rolling Deployment not ready', async () => {
    const result = await diagnosticsWith([rolled, rolling]).diagnose('proj_shop', 'prod', 'eve-acme-shop-prod');

    expect(result.deployments.map((d) => [d.name, d.ready])).toEqual([
      ['prod-web', true],
      ['prod-api', false],
    ]);
  });
});
