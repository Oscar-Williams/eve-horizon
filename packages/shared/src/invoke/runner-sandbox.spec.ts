import { describe, expect, it } from 'vitest';
import {
  RUNNER_LABELS,
  buildRunnerSandboxClaim,
  renderRunnerTemplates,
  runnerRuntimeFor,
  selectRunnerClass,
} from './runner-sandbox.js';

/**
 * agent-sandbox objects Eve renders for runner pods: one SandboxTemplate and
 * SandboxWarmPool per job class, and one SandboxClaim per attempt.
 */
const GVISOR = { key: 'sandbox.gke.io/runtime', value: 'gvisor' };

function byKind(objects: Array<Record<string, any>>, kind: string, name: string) {
  return objects.find((o) => o.kind === kind && o.metadata.name === name);
}

describe('runner job classes', () => {
  it('sends chat jobs to chat, overrides and toolchains to heavy, the rest to job', () => {
    expect(selectRunnerClass({ labels: ['chat', 'agent:review'] })).toBe('chat');
    expect(selectRunnerClass({ labels: ['chat'], resourceOverride: true })).toBe('heavy');
    expect(selectRunnerClass({ toolchains: ['python'] })).toBe('heavy');
    expect(selectRunnerClass({ labels: ['nightly'] })).toBe('job');
    expect(selectRunnerClass({})).toBe('job');
    expect(selectRunnerClass({ labels: ['chat'], hint: 'heavy' })).toBe('heavy');
  });
});

describe('runner templates', () => {
  const objects = renderRunnerTemplates({
    namespace: 'eve-runners',
    image: 'eve-horizon/worker:0.1.327',
    runtimeClass: 'gvisor',
    warmPools: { chat: 3, job: 1 },
  }) as Array<Record<string, any>>;

  it('renders a template and a warm pool per class, pools sized from the settings', () => {
    for (const cls of ['chat', 'job', 'heavy']) {
      expect(byKind(objects, 'SandboxTemplate', `eve-runner-${cls}`)).toMatchObject({
        apiVersion: 'extensions.agents.x-k8s.io/v1beta1',
        metadata: { namespace: 'eve-runners' },
        spec: { networkPolicyManagement: 'Unmanaged' },
      });
    }
    expect(byKind(objects, 'SandboxWarmPool', 'eve-runner-chat').spec).toMatchObject({ replicas: 3, sandboxTemplateRef: { name: 'eve-runner-chat' } });
    expect(byKind(objects, 'SandboxWarmPool', 'eve-runner-job').spec.replicas).toBe(1);
    expect(byKind(objects, 'SandboxWarmPool', 'eve-runner-heavy').spec.replicas).toBe(0);
  });

  it('runs every class on gVisor nodes when the instance names the runtime class', () => {
    for (const cls of ['chat', 'job', 'heavy']) {
      const spec = byKind(objects, 'SandboxTemplate', `eve-runner-${cls}`).spec.podTemplate.spec;
      expect(spec.runtimeClassName).toBe('gvisor');
      expect(spec.nodeSelector).toMatchObject({ [GVISOR.key]: GVISOR.value });
      expect(spec.tolerations).toContainEqual({ key: GVISOR.key, operator: 'Equal', value: GVISOR.value, effect: 'NoSchedule' });
      expect(spec.automountServiceAccountToken).toBe(false);
    }
  });

  it('gives chat and job an emptyDir workspace and heavy a volume claim', () => {
    const chat = byKind(objects, 'SandboxTemplate', 'eve-runner-chat').spec;
    expect(chat.podTemplate.spec.volumes).toContainEqual(expect.objectContaining({ name: 'workspace', emptyDir: expect.any(Object) }));
    expect(chat.volumeClaimTemplates).toBeUndefined();
    const heavy = byKind(objects, 'SandboxTemplate', 'eve-runner-heavy').spec;
    expect(heavy.volumeClaimTemplates).toEqual([expect.objectContaining({ metadata: expect.objectContaining({ name: 'workspace' }) })]);
    expect(heavy.podTemplate.spec.volumes.map((v: { name: string }) => v.name)).not.toContain('workspace');
  });

  it('puts no per-job value in a template, and labels every pod as a runner', () => {
    const chat = byKind(objects, 'SandboxTemplate', 'eve-runner-chat').spec.podTemplate;
    const env = chat.spec.containers[0].env.map((e: { name: string }) => e.name);
    expect(env).not.toContain('EVE_RUNNER_INBOUND_KEY_SHA256');
    expect(env).not.toContain('DATABASE_URL');
    expect(chat.metadata.labels).toMatchObject({ [RUNNER_LABELS.runner]: 'true', [RUNNER_LABELS.jobClass]: 'chat', 'eve.type': 'runner' });
  });

  it('leaves the runtime class off a class the instance opts out', () => {
    const optedOut = renderRunnerTemplates({ namespace: 'eve-runners', image: 'w', runtimeClass: 'gvisor', warmPools: {}, runtimeOptOut: ['heavy'] }) as Array<Record<string, any>>;
    expect(byKind(optedOut, 'SandboxTemplate', 'eve-runner-heavy').spec.podTemplate.spec.runtimeClassName).toBeUndefined();
    expect(byKind(optedOut, 'SandboxTemplate', 'eve-runner-job').spec.podTemplate.spec.runtimeClassName).toBe('gvisor');
  });
});

describe('runner runtime class', () => {
  it('maps gvisor to GKE Sandbox scheduling, another class to itself, and none to nothing', () => {
    expect(runnerRuntimeFor('gvisor')).toEqual({
      runtimeClassName: 'gvisor',
      nodeSelector: { [GVISOR.key]: GVISOR.value },
      tolerations: [{ key: GVISOR.key, operator: 'Equal', value: GVISOR.value, effect: 'NoSchedule' }],
    });
    expect(runnerRuntimeFor('kata')).toEqual({ runtimeClassName: 'kata' });
    expect(runnerRuntimeFor('')).toBeUndefined();
    expect(runnerRuntimeFor(null)).toBeUndefined();
  });
});

describe('runner sandbox claims', () => {
  it('claims from the class pool, labels the pod under eve.horizon, and expires after the job timeout', () => {
    const now = new Date('2026-11-20T10:00:00Z');
    const claim = buildRunnerSandboxClaim({
      name: 'eve-att-1-abcd1234', namespace: 'eve-runners', jobClass: 'chat',
      projectId: 'proj_shop', attemptId: 'att-1', jobId: 'shop-1', timeoutSeconds: 1200, now,
    }) as Record<string, any>;
    expect(claim).toMatchObject({
      apiVersion: 'extensions.agents.x-k8s.io/v1beta1',
      kind: 'SandboxClaim',
      metadata: { name: 'eve-att-1-abcd1234', namespace: 'eve-runners' },
      spec: {
        warmPoolRef: { name: 'eve-runner-chat' },
        additionalPodMetadata: { labels: {
          [RUNNER_LABELS.projectId]: 'proj_shop', [RUNNER_LABELS.attemptId]: 'att-1', [RUNNER_LABELS.jobClass]: 'chat',
        } },
        lifecycle: { shutdownPolicy: 'Delete' },
      },
    });
    const shutdown = new Date(claim.spec.lifecycle.shutdownTime).getTime();
    expect(shutdown - now.getTime()).toBeGreaterThan(1200 * 1000);
    expect(shutdown - now.getTime()).toBeLessThanOrEqual((1200 + 15 * 60) * 1000);
    expect(claim.spec.env).toBeUndefined();
    for (const key of Object.keys(claim.spec.additionalPodMetadata.labels)) expect(key.startsWith('eve.horizon/')).toBe(true);
  });
});
