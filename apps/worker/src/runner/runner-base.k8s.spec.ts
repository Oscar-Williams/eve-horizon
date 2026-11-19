import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { parseAllDocuments } from 'yaml';

/**
 * k8s/base for runner pods: they run as `eve-runner`, an account with no
 * token mount and no RBAC, never as the worker's own account; and the worker
 * and agent runtime refuse to start when job processes could read their
 * environment.
 */
type Manifest = { kind: string; metadata: { name: string; namespace?: string }; automountServiceAccountToken?: boolean;
  subjects?: Array<{ kind: string; name: string }>; spec?: any };

const baseDir = join(__dirname, '..', '..', '..', '..', 'k8s', 'base');
const manifests: Manifest[] = readdirSync(baseDir)
  .filter((file) => file.endsWith('.yaml'))
  .flatMap((file) => parseAllDocuments(readFileSync(join(baseDir, file), 'utf8'))
    .map((doc) => doc.toJSON() as Manifest | null)
    .filter((doc): doc is Manifest => doc !== null));

function envOf(name: string): Record<string, string | undefined> {
  const workload = manifests.find((m) => ['Deployment', 'StatefulSet'].includes(m.kind) && m.metadata.name === name);
  if (!workload) throw new Error(`k8s/base has no workload ${name}`);
  const env = workload.spec.template.spec.containers[0].env as Array<{ name: string; value?: string }>;
  return Object.fromEntries(env.map((e) => [e.name, e.value]));
}

describe('k8s/base runner identity', () => {
  it('defines eve-runner with no token mount and binds it to no role', () => {
    const account = manifests.find((m) => m.kind === 'ServiceAccount' && m.metadata.name === 'eve-runner');
    expect(account).toBeDefined();
    expect(account!.automountServiceAccountToken).toBe(false);
    const bound = manifests
      .filter((m) => m.kind === 'RoleBinding' || m.kind === 'ClusterRoleBinding')
      .flatMap((m) => m.subjects ?? [])
      .filter((s) => s.kind === 'ServiceAccount' && s.name === 'eve-runner');
    expect(bound).toEqual([]);
  });

  it('runs runner pods as eve-runner', () => {
    expect(envOf('eve-worker').EVE_RUNNER_SERVICE_ACCOUNT).toBe('eve-runner');
  });

  it('makes the worker and agent runtime refuse to start with a readable environment', () => {
    expect(envOf('eve-worker').EVE_REQUIRE_ENVIRON_PROTECTION).toBe('true');
    expect(envOf('eve-agent-runtime').EVE_REQUIRE_ENVIRON_PROTECTION).toBe('true');
  });
});
