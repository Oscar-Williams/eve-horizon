import { describe, expect, it, vi } from 'vitest';
import { Logger } from '@nestjs/common';
import { ActionExecutorService } from './action-executor.service.js';
import { DeployFailureError } from '../deployer/deploy-failure.js';
import { DeployerService } from '../deployer/deployer.service.js';
import { K8sService } from '../deployer/k8s.service.js';

describe('ActionExecutorService deploy readiness failure', () => {
  it('throws a classified DeployFailureError with cluster snapshot on readiness timeout', async () => {
    const deployer = {
      getDeploymentStatus: vi.fn().mockResolvedValue({
        envId: 'env_1',
        state: 'deploying',
        namespace: 'eve-proj-staging',
        k8sStatus: {
          ready: false,
          availableReplicas: 0,
          desiredReplicas: 1,
          conditions: [],
        },
      }),
      collectClusterSnapshot: vi.fn().mockResolvedValue({
        namespace: 'eve-proj-staging',
        capturedAt: '2026-04-21T12:00:00.000Z',
        pods: [
          {
            name: 'api-123',
            namespace: 'eve-proj-staging',
            phase: 'Running',
            ready: false,
            restartCount: 5,
            service: 'api',
            containers: [
              {
                name: 'api',
                ready: false,
                restartCount: 5,
                state: 'waiting',
                waitingReason: 'CrashLoopBackOff',
                lastTerminatedExitCode: 1,
                lastTerminatedReason: 'Error',
              },
            ],
          },
        ],
      }),
    };

    const service = new ActionExecutorService(null as any, deployer as any, {} as any);
    (service as any).envs = {
      findById: vi.fn().mockResolvedValue({
        id: 'env_1',
        project_id: 'proj_1',
        name: 'staging',
      }),
    };
    (service as any).logs = {
      appendLog: vi.fn().mockResolvedValue(undefined),
    };

    let thrown: unknown;
    try {
      await (service as any).waitForDeployReady('env_1', 0, 'att_1');
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(DeployFailureError);
    expect(thrown).toMatchObject({
      name: 'DeployFailureError',
      manifestApplied: true,
      failure: {
        kind: 'app_crash_loop',
        service: 'api',
        pod: 'api-123',
      },
      snapshot: {
        namespace: 'eve-proj-staging',
      },
    });
  });

  it('fails at the timeout when the new ReplicaSet never becomes available, though the old pod stays available', async () => {
    const namespace = 'eve-acme-shop-prod';
    // One desired; the old pod is available, the new one never is.
    const apiDeployment = {
      metadata: { name: 'prod-api', generation: 2 },
      spec: { replicas: 1 },
      status: { observedGeneration: 2, replicas: 2, updatedReplicas: 1, availableReplicas: 1, conditions: [] },
    };
    const k8s = new K8sService();
    Object.assign(k8s as any, {
      available: true,
      appsApi: { listNamespacedDeployment: vi.fn(async () => ({ body: { items: [apiDeployment] } })) },
    });
    const deployer = Object.create(DeployerService.prototype) as DeployerService;
    Object.assign(deployer as any, {
      k8sService: k8s,
      logger: new Logger('test'),
      resolveEnvironmentScope: vi.fn(async () => ({
        namespace,
        environment: { id: 'env_1', current_release_id: 'rel_1' },
      })),
      collectClusterSnapshot: vi.fn().mockResolvedValue({
        namespace,
        capturedAt: '2026-11-20T12:00:00.000Z',
        pods: [
          {
            name: 'prod-api-old',
            namespace,
            phase: 'Running',
            ready: true,
            restartCount: 0,
            service: 'api',
            containers: [{ name: 'api', ready: true, restartCount: 0, state: 'running' }],
          },
          {
            name: 'prod-api-new',
            namespace,
            phase: 'Running',
            ready: false,
            restartCount: 0,
            service: 'api',
            containers: [{ name: 'api', ready: false, restartCount: 0, state: 'running' }],
          },
        ],
      }),
    });

    const service = new ActionExecutorService(null as any, deployer, {} as any);
    (service as any).envs = {
      findById: vi.fn().mockResolvedValue({ id: 'env_1', project_id: 'proj_shop', name: 'prod' }),
    };
    (service as any).logs = { appendLog: vi.fn().mockResolvedValue(undefined) };

    let thrown: unknown;
    try {
      await (service as any).waitForDeployReady('env_1', 0, 'att_1');
    } catch (error) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(DeployFailureError);
    expect(thrown).toMatchObject({
      manifestApplied: true,
      failure: { kind: 'readiness_timeout', notReady: ['prod-api-new'] },
    });
    // The message names the Deployment still rolling.
    expect((thrown as DeployFailureError).failure.message).toMatch(/still rolling: prod-api$/);
  });

  it('does not advance last_applied_release_id for pre-apply deploy failures', async () => {
    const update = vi.fn().mockResolvedValue(null);
    const service = new ActionExecutorService(null as any, {} as any, {} as any);
    (service as any).envs = { update };

    await (service as any).recordDeployFailure(
      'env_1',
      'rel_1',
      new Error('namespace create failed'),
    );

    expect(update).toHaveBeenCalledWith(
      'env_1',
      expect.objectContaining({
        last_applied_release_id: undefined,
        last_failed_release_id: 'rel_1',
        deploy_status: 'failed',
      }),
    );
  });
});
