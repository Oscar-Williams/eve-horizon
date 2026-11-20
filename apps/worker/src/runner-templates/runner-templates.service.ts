import { Inject, Injectable, Logger, type OnApplicationBootstrap } from '@nestjs/common';
import { type Db, systemSettingsQueries } from '@eve/db';
import {
  DEFAULT_RUNNER_NAMESPACE,
  RUNNER_CLASSES,
  RUNNER_SETTINGS,
  renderRunnerTemplates,
  resolveRunnerPodIsolation,
  type RunnerClass,
} from '@eve/shared';
import { execKubectl } from '../invoke/k8s-runner.js';
import { resetSandboxDiscovery, sandboxCrdsPresent } from '../invoke/sandbox-claim-backend.js';

export interface RunnerTemplatesReport {
  backend: 'sandbox' | 'pod';
  namespace: string;
  reason?: string;
  applied?: string[];
  runtime_class?: string | null;
  warm_pools?: Partial<Record<RunnerClass, number>>;
}

/**
 * The runner SandboxTemplates and SandboxWarmPools, one per job class,
 * rendered from this worker's runner image (EVE_RUNNER_IMAGE) and the
 * instance settings, and applied in the runner namespace. The worker applies
 * them at startup, so a release's runner image follows the release, and on
 * `eve system security reconcile`, so changed settings take effect. Without
 * the agent-sandbox CRDs it does nothing: runner pods are created directly.
 *
 * Settings: `runner.runtime_class` (for example `gvisor`),
 * `runner.runtime_class_opt_out` (classes that run without it, comma
 * separated), `runner.warm_pool.chat` and `runner.warm_pool.job` (warm pool
 * sizes; default 0; heavy is always cold).
 */
@Injectable()
export class RunnerTemplatesService implements OnApplicationBootstrap {
  private readonly logger = new Logger(RunnerTemplatesService.name);

  constructor(@Inject('DB') private readonly db: Db) {}

  onApplicationBootstrap(): void {
    if (process.env.EVE_RUNTIME !== 'k8s') return;
    void this.reconcile()
      .then((report) => this.logger.log(`Runner templates: ${report.backend}${report.reason ? ` (${report.reason})` : ''}`))
      .catch((err) => this.logger.warn(`Runner templates not reconciled: ${err instanceof Error ? err.message : String(err)}`));
  }

  async reconcile(): Promise<RunnerTemplatesReport> {
    const namespace = process.env.EVE_RUNNER_NAMESPACE || DEFAULT_RUNNER_NAMESPACE;
    resetSandboxDiscovery();
    if (!(await sandboxCrdsPresent())) {
      return { backend: 'pod', namespace, reason: 'the agent-sandbox CRDs are not installed' };
    }
    const image = process.env.EVE_RUNNER_IMAGE;
    if (!image) throw new Error('EVE_RUNNER_IMAGE is not set on the worker');

    const settings = systemSettingsQueries(this.db);
    const read = async (key: string) => (await settings.get(key))?.value?.trim() || null;
    const runtimeClass = await read(RUNNER_SETTINGS.runtimeClass);
    const optOut = ((await read(RUNNER_SETTINGS.runtimeOptOut)) ?? '').split(/[\s,]+/)
      .filter((cls): cls is RunnerClass => (RUNNER_CLASSES as readonly string[]).includes(cls));
    const warmPools: Partial<Record<RunnerClass, number>> = {};
    for (const cls of RUNNER_CLASSES) {
      const size = Number.parseInt((await read(RUNNER_SETTINGS.warmPool(cls))) ?? '0', 10);
      warmPools[cls] = Number.isFinite(size) && size > 0 ? Math.min(size, 50) : 0;
    }

    const objects = renderRunnerTemplates({
      namespace, image, runtimeClass, runtimeOptOut: optOut, warmPools, isolation: resolveRunnerPodIsolation(),
      // The heavy class's workspace claim, as a heavy plain pod's.
      heavyWorkspaceSize: process.env.EVE_K8S_WORKSPACE_SIZE || undefined,
    });
    const applied = await execKubectl(['apply', '-f', '-'], JSON.stringify({ apiVersion: 'v1', kind: 'List', items: objects }));
    if (applied.exitCode !== 0) throw new Error(`Runner templates were not applied: ${applied.stderr || applied.stdout}`);
    resetSandboxDiscovery();
    return {
      backend: 'sandbox',
      namespace,
      applied: objects.map((o) => `${o.kind}/${(o.metadata as { name: string }).name}`),
      runtime_class: runtimeClass,
      warm_pools: warmPools,
    };
  }
}
