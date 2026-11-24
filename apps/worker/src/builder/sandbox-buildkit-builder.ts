import { Injectable } from '@nestjs/common';
import { randomUUID } from 'node:crypto';
import { isIP } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { execKubectl, parseDurationMs } from '../invoke/k8s-runner.js';
import { BuildKitBuilder } from './buildkit-builder.js';
import type { BuildAllParams, BuildBackend, BuildResult, BuildServiceParams } from './image-builder.interface.js';

export const ROOTLESS_BUILDKIT_IMAGE = 'moby/buildkit@sha256:f68752a5a94acfcdad2d07867b7075601a421638e17fc5f28efc1c814d0c4f89';
const CLAIM_RESOURCE = 'sandboxclaims.extensions.agents.x-k8s.io';
const POOL_RESOURCE = 'sandboxwarmpools.extensions.agents.x-k8s.io';
const CLAIM_LABEL = 'eve.horizon/build-claim';
const PROJECT_LABEL = 'eve.horizon/project-id';
const TERMINAL_REASONS = new Set([
  'TemplateNotFound', 'WarmPoolNotFound', 'InvalidMetadata', 'EnvVarsInjectionRejected',
  'VolumeClaimTemplatesError', 'ClaimExpired', 'SandboxExpired', 'InvalidConfiguration', 'PodFailed',
]);

type Claim = { status?: {
  conditions?: Array<{ type: string; status: string; reason?: string }>;
  sandbox?: { name?: string; podIPs?: string[] };
} };
type SecurityContext = {
  runAsUser?: number; runAsGroup?: number; runAsNonRoot?: boolean; privileged?: boolean;
  capabilities?: { add?: string[] };
};
type Pod = {
  metadata?: { name?: string; deletionTimestamp?: string; labels?: Record<string, string>;
    ownerReferences?: Array<{ kind: string; name: string; controller?: boolean }> };
  spec?: {
    runtimeClassName?: string; automountServiceAccountToken?: boolean;
    hostNetwork?: boolean; hostPID?: boolean; hostIPC?: boolean;
    securityContext?: SecurityContext; initContainers?: unknown[]; ephemeralContainers?: unknown[];
    volumes?: Array<Record<string, unknown>>; imagePullSecrets?: unknown[];
    containers?: Array<{ name: string; image: string; securityContext?: SecurityContext;
      ports?: Array<{ hostPort?: number }>; envFrom?: unknown[]; env?: unknown[] }>;
  };
  status?: { phase?: string; podIP?: string; podIPs?: Array<{ ip: string }>;
    conditions?: Array<{ type: string; status: string }> };
};

function duration(name: string, fallback: string): number {
  const ms = parseDurationMs(process.env[name] ?? fallback, name);
  if (!Number.isSafeInteger(ms) || ms <= 0 || ms > 86_400_000) throw new Error(`Invalid ${name}: must be positive and at most 24h`);
  return ms;
}

/** Credential-free controller requests. Never falls back to a shared daemon. */
@Injectable()
export class SandboxBuildKitBuilder implements BuildBackend {
  readonly kind = 'sandbox' as const;
  constructor(private readonly client: BuildKitBuilder) {}

  async buildAll(_params: BuildAllParams): Promise<BuildResult> {
    throw new Error('Use ImageBuilderService.buildAll() instead');
  }

  async buildService(params: BuildServiceParams): Promise<string> {
    params.signal?.throwIfAborted();
    // Project ids are also cache tags and admission/network labels; never truncate them.
    if (!/^[a-z0-9][a-z0-9_-]{0,61}[a-z0-9]$/.test(params.projectId)) throw new Error('Invalid builder projectId');
    const namespace = process.env.EVE_BUILD_SANDBOX_NAMESPACE ?? 'eve-builds';
    const template = process.env.EVE_BUILD_SANDBOX_TEMPLATE ?? 'eve-builder';
    const runtime = process.env.EVE_BUILD_RUNTIME_CLASS ?? 'gvisor';
    const image = process.env.EVE_BUILD_SANDBOX_IMAGE ?? ROOTLESS_BUILDKIT_IMAGE;
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(namespace) ||
        !/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(template) || !runtime ||
        !/^[^\s@]+@sha256:[a-f0-9]{64}$/.test(image)) {
      throw new Error('Invalid builder namespace, template, runtime class or digest-pinned image');
    }
    const timeoutMs = duration('EVE_BUILD_TIMEOUT', '30m');
    const readyMs = duration('EVE_BUILD_READY_TIMEOUT', '5m');
    const deadline = new AbortController();
    const timer = setTimeout(() => deadline.abort(new Error('build_timeout: sandbox build deadline exceeded')), timeoutMs);
    timer.unref();
    const signal = params.signal ? AbortSignal.any([params.signal, deadline.signal]) : deadline.signal;
    const name = `eve-build-${randomUUID()}`;
    const labels = { [CLAIM_LABEL]: name, [PROJECT_LABEL]: params.projectId, 'eve.type': 'builder' };
    const ns = `--namespace=${namespace}`;
    let attemptedCreate = false;
    let failure: unknown;
    try {
      const pool = JSON.parse(await this.kubectl(['get', POOL_RESOURCE, template, ns, '-o', 'json'], signal));
      if (pool.spec?.replicas !== 0 || pool.spec?.sandboxTemplateRef?.name !== template) {
        throw new Error('Builder pool must have replicas=0 and reference its matching template');
      }
      const claim = {
        apiVersion: 'extensions.agents.x-k8s.io/v1beta1', kind: 'SandboxClaim',
        metadata: { name, namespace, labels },
        spec: {
          warmPoolRef: { name: template },
          additionalPodMetadata: { labels },
          // Controller cleanup also covers a worker crash; allow time for normal cleanup.
          lifecycle: { shutdownTime: new Date(Date.now() + timeoutMs + 60_000).toISOString(), shutdownPolicy: 'Delete' },
        },
      };
      attemptedCreate = true; // A request may be accepted even if its response is lost.
      await this.kubectl(['create', '-f', '-'], signal, JSON.stringify(claim));
      params.onLog?.(`Builder claim: ${namespace}/${name}`);
      const readyDeadline = Date.now() + readyMs;
      while (Date.now() < readyDeadline) {
        signal.throwIfAborted();
        const claimState = JSON.parse(await this.kubectl(['get', CLAIM_RESOURCE, name, ns, '-o', 'json'], signal)) as Claim;
        const ready = claimState.status?.conditions?.find((c) => c.type === 'Ready');
        if (ready?.status === 'False' && ready.reason && TERMINAL_REASONS.has(ready.reason)) {
          throw new Error(`Builder claim failed: ${ready.reason}`);
        }
        const sandbox = claimState.status?.sandbox;
        const ip = sandbox?.podIPs?.[0];
        if (ready?.status === 'True' && ip && sandbox?.name) {
          if (!isIP(ip)) throw new Error('Builder claim reported an invalid pod IP');
          const list = JSON.parse(await this.kubectl(['get', 'pods', ns, '-l', `${CLAIM_LABEL}=${name}`, '-o', 'json'], signal)) as { items?: Pod[] };
          const pod = list.items?.find((p) => p.status?.podIP === ip || p.status?.podIPs?.some((v) => v.ip === ip));
          if (pod) {
            this.verifyPod(pod, name, params.projectId, sandbox.name, runtime, image);
            if (pod.status?.conditions?.some((c) => c.type === 'Ready' && c.status === 'True')) {
              params.onLog?.(`Builder pod: ${namespace}/${pod.metadata!.name} (${runtime})`);
              const digest = await this.client.buildServiceAt({ ...params, signal }, `tcp://${isIP(ip) === 6 ? `[${ip}]` : ip}:1234`, true);
              signal.throwIfAborted();
              return digest;
            }
          }
        }
        await delay(500, undefined, { signal });
      }
      throw new Error(`build_timeout: builder was not Ready within ${readyMs}ms`);
    } catch (error) {
      failure = signal.aborted ? signal.reason : error;
      throw failure;
    } finally {
      clearTimeout(timer);
      if (attemptedCreate) {
        // Cleanup must run even when the job's signal has already been aborted.
        try {
          await this.kubectl(['delete', CLAIM_RESOURCE, name, ns, '--ignore-not-found=true', '--cascade=foreground', '--wait=true', '--timeout=30s'], AbortSignal.timeout(35_000));
          params.onLog?.(`Builder claim deleted: ${namespace}/${name}`);
        } catch (cleanup) {
          const message = `builder_cleanup_failed: ${namespace}/${name}: ${cleanup instanceof Error ? cleanup.message : String(cleanup)}`;
          throw new Error(failure ? `${failure instanceof Error ? failure.message : String(failure)}; ${message}` : message);
        }
      }
    }
  }

  private async kubectl(args: string[], signal: AbortSignal, input?: string): Promise<string> {
    signal.throwIfAborted();
    const result = await execKubectl(args, input, signal);
    if (result.exitCode !== 0) throw new Error(`Builder Kubernetes request failed (${args[0]} ${args[1]}): ${result.stderr || result.stdout}`);
    return result.stdout;
  }

  /** Check the claimed endpoint before a buildctl session can use registry auth. */
  private verifyPod(pod: Pod, claim: string, projectId: string, sandbox: string, runtime: string, image: string): void {
    const spec = pod.spec;
    const container = spec?.containers?.[0];
    const security = { ...spec?.securityContext, ...container?.securityContext };
    if (!pod.metadata?.name || pod.metadata.deletionTimestamp ||
        pod.metadata.labels?.[CLAIM_LABEL] !== claim || pod.metadata.labels?.[PROJECT_LABEL] !== projectId ||
        !pod.metadata.ownerReferences?.some((o) => o.kind === 'Sandbox' && o.name === sandbox && o.controller) ||
        spec?.runtimeClassName !== runtime || spec.automountServiceAccountToken !== false ||
        spec.hostNetwork || spec.hostPID || spec.hostIPC ||
        spec.containers?.length !== 1 || spec.initContainers?.length || spec.ephemeralContainers?.length ||
        container?.name !== 'buildkit' || container.image !== image ||
        security.runAsUser !== 1000 || security.runAsGroup !== 1000 || security.runAsNonRoot !== true ||
        security.privileged || security.capabilities?.add?.length ||
        container.envFrom?.length || container.env?.length || spec.imagePullSecrets?.length ||
        container.ports?.some((p) => p.hostPort) ||
        !spec.volumes?.length || spec.volumes.some((v) => !v.emptyDir || Object.keys(v).some((k) => k !== 'name' && k !== 'emptyDir')) ||
        pod.status?.phase === 'Failed' || pod.status?.phase === 'Succeeded') {
      throw new Error('Builder pod does not match the isolated rootless template');
    }
  }
}
