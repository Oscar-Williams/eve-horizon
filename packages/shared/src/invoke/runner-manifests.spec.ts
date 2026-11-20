import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { buildRunnerPod, RUNNER_CONTAINER_ARGS } from './runner-manifests.js';
import { createRunnerInboundKey, runnerInboundKeyMatches } from './runner-protocol.js';
import { resolveRunnerPodIsolation } from './runner-pod.js';
import { renderRunnerTemplates } from './runner-sandbox.js';

/**
 * Runner pods run job code. The one pod builder both dispatch paths use puts
 * no platform credential in the pod: no database URL, no internal key (or its
 * hash), no forwarded EVE_WORKER_* or EVE_HARNESS_* settings, and the inbound
 * key the worker submits with appears only as its SHA-256.
 */
const PLATFORM = {
  DATABASE_URL: 'postgres://eve:secret@db/eve',
  EVE_INTERNAL_API_KEY: 'legacy-internal-key',
  EVE_INTERNAL_CORE_KEY: 'core-internal-key',
  EVE_SECRETS_MASTER_KEY: 'master-key',
  EVE_WORKER_DEBUG: 'worker-setting',
  EVE_HARNESS_MODEL: 'harness-setting',
  EVE_API_URL: 'http://eve-api.eve.svc:4701',
};
const previous: Record<string, string | undefined> = {};

beforeEach(() => {
  for (const [key, value] of Object.entries(PLATFORM)) {
    previous[key] = process.env[key];
    process.env[key] = value;
  }
});
afterEach(() => {
  for (const key of Object.keys(PLATFORM)) {
    if (previous[key] === undefined) delete process.env[key];
    else process.env[key] = previous[key];
  }
});

function pod(overrides: Partial<Parameters<typeof buildRunnerPod>[0]> = {}) {
  const inbound = createRunnerInboundKey();
  const manifest = buildRunnerPod({
    name: 'eve-runner-att-1',
    namespace: 'eve-runners',
    image: 'eve-horizon/worker:test',
    labels: { 'eve.horizon/project-id': 'proj_shop', 'eve.horizon/attempt-id': 'att-1' },
    inboundKeySha256: inbound.sha256,
    workspace: { kind: 'emptyDir' },
    ...overrides,
  });
  return { manifest, inbound, container: manifest.spec.containers[0] };
}

describe('runner pod builder', () => {
  it('carries no platform credential and no forwarded service settings', () => {
    const { manifest, container } = pod();
    const names = (container.env ?? []).map((entry: { name: string }) => entry.name);
    for (const name of ['DATABASE_URL', 'EVE_INTERNAL_API_KEY', 'EVE_INTERNAL_CORE_KEY', 'EVE_INTERNAL_CALLER_HASHES',
      'EVE_SECRETS_MASTER_KEY', 'EVE_WORKER_DEBUG', 'EVE_HARNESS_MODEL']) {
      expect(names).not.toContain(name);
    }
    const serialized = JSON.stringify(manifest);
    for (const value of Object.values(PLATFORM).filter((v) => !v.startsWith('http'))) {
      expect(serialized).not.toContain(value);
    }
    expect(serialized).not.toContain(createHash('sha256').update('core-internal-key').digest('hex'));
  });

  it('holds the inbound key only as its hash', () => {
    const { manifest, inbound, container } = pod();
    expect(container.env).toContainEqual({ name: 'EVE_RUNNER_INBOUND_KEY_SHA256', value: inbound.sha256 });
    expect(JSON.stringify(manifest)).not.toContain(inbound.key);
    expect(runnerInboundKeyMatches(inbound.key, inbound.sha256)).toBe(true);
    expect(runnerInboundKeyMatches('another-key', inbound.sha256)).toBe(false);
    expect(runnerInboundKeyMatches(undefined, inbound.sha256)).toBe(false);
  });

  it('starts the runner entrypoint, not the worker app', () => {
    const { container } = pod();
    expect(container.args).toEqual(RUNNER_CONTAINER_ARGS);
    expect(RUNNER_CONTAINER_ARGS.join(' ')).toContain('dist/runner/main.js');
  });

  it('runs restricted, with no service account token', () => {
    const { manifest, container } = pod();
    expect(manifest.spec).toMatchObject({ automountServiceAccountToken: false, enableServiceLinks: false,
      securityContext: { runAsNonRoot: true, seccompProfile: { type: 'RuntimeDefault' } } });
    expect(container.securityContext).toMatchObject({ runAsNonRoot: true, allowPrivilegeEscalation: false,
      capabilities: { drop: ['ALL'] } });
  });

  it('mounts no org filesystem unless asked, and read-only unless the job writes', () => {
    const none = pod().manifest.spec;
    expect(none.volumes.map((v: { name: string }) => v.name)).not.toContain('org-fs');

    const readOnly = pod({ orgFs: { readOnly: true } }).container;
    expect(readOnly.volumeMounts).toContainEqual({ name: 'org-fs', mountPath: '/org', readOnly: true });
    const writable = pod({ orgFs: { readOnly: false } }).container;
    expect(writable.volumeMounts).toContainEqual({ name: 'org-fs', mountPath: '/org', readOnly: false });
  });

  it('refuses to start unless job processes cannot read its environment', () => {
    expect(pod().container.env).toContainEqual({ name: 'EVE_REQUIRE_ENVIRON_PROTECTION', value: 'true' });
    const templates = renderRunnerTemplates({ namespace: 'eve-runners', image: 'w', warmPools: {} }) as Array<Record<string, any>>;
    for (const template of templates.filter((o) => o.kind === 'SandboxTemplate')) {
      expect(template.spec.podTemplate.spec.containers[0].env).toContainEqual({ name: 'EVE_REQUIRE_ENVIRON_PROTECTION', value: 'true' });
    }
  });

  it('co-locates only a pod that mounts the org filesystem with the pod holding it', () => {
    const isolation = resolveRunnerPodIsolation({
      EVE_RUNNER_POD_AFFINITY_KEY: 'app.kubernetes.io/name', EVE_RUNNER_POD_AFFINITY_VALUE: 'eve-agent-runtime',
    } as NodeJS.ProcessEnv);
    expect(pod({ isolation, orgFs: { readOnly: true } }).manifest.spec.affinity).toEqual(isolation.affinity);
    expect(pod({ isolation }).manifest.spec.affinity).toBeUndefined();
    const templates = renderRunnerTemplates({ namespace: 'eve-runners', image: 'w', warmPools: {}, isolation }) as Array<Record<string, any>>;
    for (const template of templates.filter((o) => o.kind === 'SandboxTemplate')) {
      expect(template.spec.podTemplate.spec.affinity).toBeUndefined();
    }
  });
});
