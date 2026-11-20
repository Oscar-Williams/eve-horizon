import { describe, expect, it, vi } from 'vitest';
import { Logger } from '@nestjs/common';
import { K8sService } from '../k8s.service.js';
import { DeploymentReadiness } from '../deployment-readiness.js';

/**
 * "Ready" means the new pods serve, as `kubectl rollout status` judges it.
 * Right after an apply the old ReplicaSet's pods are still available; they
 * must not make a Deployment, or its namespace, ready.
 */
interface Shape {
  name: string;
  generation?: number;
  observedGeneration?: number;
  desired: number;
  replicas?: number;
  updated?: number;
  available?: number;
}

function deployment(d: Shape) {
  const generation = d.generation ?? 1;
  return {
    metadata: { name: d.name, generation },
    spec: { replicas: d.desired },
    status: {
      observedGeneration: d.observedGeneration ?? generation,
      replicas: d.replicas,
      updatedReplicas: d.updated,
      availableReplicas: d.available,
      conditions: [],
    },
  };
}

function k8sWith(...deployments: Array<ReturnType<typeof deployment>>): K8sService {
  const appsApi = {
    readNamespacedDeployment: vi.fn(async (name: string) => ({
      body: deployments.find((d) => d.metadata.name === name),
    })),
    listNamespacedDeployment: vi.fn(async () => ({ body: { items: deployments } })),
  };
  const k8s = new K8sService();
  Object.assign(k8s as any, { appsApi, available: true });
  return k8s;
}

const NS = 'eve-acme-shop-prod';

const cases: Array<[string, Shape, boolean]> = [
  [
    'generation 3, observed 2, 1 of 1 available: not ready',
    { name: 'prod-web', generation: 3, observedGeneration: 2, desired: 1, replicas: 1, updated: 1, available: 1 },
    false,
  ],
  [
    '1 desired, 2 pods, 1 updated, 2 available (old pod up): not ready',
    { name: 'prod-web', generation: 3, desired: 1, replicas: 2, updated: 1, available: 2 },
    false,
  ],
  [
    'generation 3, observed 3, 1 desired, 1 pod, 1 updated, 1 available: ready',
    { name: 'prod-web', generation: 3, observedGeneration: 3, desired: 1, replicas: 1, updated: 1, available: 1 },
    true,
  ],
  [
    '0 desired: ready',
    { name: 'prod-web', generation: 4, observedGeneration: 3, desired: 0, replicas: 1, updated: 0, available: 1 },
    true,
  ],
];

describe('K8sService.getDeploymentStatus waits for the new pods', () => {
  it.each(cases)('one Deployment: %s', async (_label, shape, ready) => {
    const status = await k8sWith(deployment(shape)).getDeploymentStatus(NS, 'prod-web');
    expect(status.ready).toBe(ready);
  });

  it.each(cases)('the namespace: %s', async (_label, shape, ready) => {
    const status = await k8sWith(deployment(shape)).getDeploymentStatus(NS);
    expect(status.ready).toBe(ready);
    expect(status.rolling).toEqual(ready ? [] : ['prod-web']);
  });
});

describe('DeploymentReadiness', () => {
  it('a namespace with one Deployment rolled and one still rolling is not ready', async () => {
    const k8s = k8sWith(
      deployment({ name: 'prod-web', generation: 2, desired: 1, replicas: 1, updated: 1, available: 1 }),
      // The new api pod is not available yet; the old one still is.
      deployment({ name: 'prod-api', generation: 2, desired: 1, replicas: 2, updated: 1, available: 1 }),
    );
    const readiness = new DeploymentReadiness(k8s, new Logger('test'));

    const status = await readiness.waitForDeploymentReadiness(NS, 0);

    expect(status.ready).toBe(false);
    expect(status.rolling).toEqual(['prod-api']);
  });
});
