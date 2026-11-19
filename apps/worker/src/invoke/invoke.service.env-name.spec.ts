import { describe, expect, it, vi } from 'vitest';
import type { HarnessInvocation } from '@eve/shared';
import { InvokeService } from './invoke.service.js';

/**
 * The environment an agent job runs against, as the agent runtime decides it:
 * the job's own env_name first, then the manifest's default env. The worker
 * path used only the manifest default, so a job targeting another
 * environment got the wrong EVE_ENV_NAME and env-release git ref.
 */
function service(jobEnv: string | null) {
  const db = Object.assign(vi.fn(async (strings: TemplateStringsArray) => (strings.join('?').includes('project_manifests')
    ? [{ parsed_defaults: { env: 'prod' } }] : [])), { json: (v: unknown) => v });
  const svc = new InvokeService(db as never);
  (svc as unknown as Record<string, unknown>).jobs = { findById: vi.fn(async () => ({ id: 'shop-1', env_name: jobEnv })) };
  return svc as unknown as { applyManifestDefaults(inv: HarnessInvocation): Promise<HarnessInvocation> };
}

const invocation = { jobId: 'shop-1', attemptId: 'att-1', projectId: 'proj_shop', text: 'go', data: {} } as unknown as HarnessInvocation;

describe('the environment of an agent job the worker runs', () => {
  it("is the job's own env_name when it has one", async () => {
    expect((await service('staging').applyManifestDefaults(invocation)).data?.env_name).toBe('staging');
  });

  it("is the manifest's default env otherwise", async () => {
    expect((await service(null).applyManifestDefaults(invocation)).data?.env_name).toBe('prod');
  });

  it('keeps an env_name the invocation already names', async () => {
    const named = { ...invocation, data: { env_name: 'qa' } } as unknown as HarnessInvocation;
    expect((await service('staging').applyManifestDefaults(named)).data?.env_name).toBe('qa');
  });
});
