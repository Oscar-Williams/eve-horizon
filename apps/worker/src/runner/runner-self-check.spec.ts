import { describe, expect, it, vi } from 'vitest';
import { egressSelfCheck } from './runner-self-check.js';

/**
 * Before a runner uses its job's token it checks that the metadata server
 * and the Kubernetes API are out of reach. Under enforce (the project's
 * strict isolation.runner_mode) a reachable one fails the job; under audit
 * it is recorded and the job runs; off skips the check.
 */
const submit = (mode: 'enforce' | 'audit' | 'off' | undefined) => ({
  kind: 'agent' as const, job_id: 'shop-1', attempt_id: 'att-1', project_id: 'proj_shop',
  job_token: 't', api_url: 'http://api.test', self_check: mode,
});

function client() {
  return { updateRuntimeMeta: vi.fn(async () => undefined), appendLogs: vi.fn(async () => undefined) };
}

describe('runner egress self-check', () => {
  it('fails the job under enforce when the metadata server answers', async () => {
    const probe = vi.fn(async (host: string) => host === '169.254.169.254');
    const c = client();
    const refusal = await egressSelfCheck({ probe, kubernetesHost: '10.0.0.1' })(submit('enforce'), c as never);
    expect(refusal).toMatchObject({ success: false, error: expect.stringMatching(/egress policy not enforced/) });
    expect(c.updateRuntimeMeta).toHaveBeenCalledWith({ self_check: expect.objectContaining({ metadata_reachable: true, kubernetes_reachable: false, mode: 'enforce' }) });
  });

  it('fails the job under enforce when the Kubernetes API answers', async () => {
    const probe = vi.fn(async (host: string, port: number) => host === '10.0.0.1' && port === 443);
    const refusal = await egressSelfCheck({ probe, kubernetesHost: '10.0.0.1' })(submit('enforce'), client() as never);
    expect(refusal?.error).toMatch(/egress policy not enforced/);
  });

  it('lets the job run when both are out of reach', async () => {
    const probe = vi.fn(async () => false);
    expect(await egressSelfCheck({ probe, kubernetesHost: '10.0.0.1' })(submit('enforce'), client() as never)).toBeNull();
    expect(probe).toHaveBeenCalledWith('169.254.169.254', 80);
    expect(probe).toHaveBeenCalledWith('10.0.0.1', 443);
  });

  it('records but runs under audit, and skips the check when off', async () => {
    const probe = vi.fn(async () => true);
    const c = client();
    expect(await egressSelfCheck({ probe, kubernetesHost: '10.0.0.1' })(submit('audit'), c as never)).toBeNull();
    expect(c.updateRuntimeMeta).toHaveBeenCalledWith({ self_check: expect.objectContaining({ mode: 'audit', metadata_reachable: true }) });
    probe.mockClear();
    expect(await egressSelfCheck({ probe, kubernetesHost: '10.0.0.1' })(submit('off'), client() as never)).toBeNull();
    expect(probe).not.toHaveBeenCalled();
  });

  it('records the mode before job code runs when the check is off or unset, so job code has no slot to fill', async () => {
    const probe = vi.fn(async () => true);
    for (const mode of ['off', undefined] as const) {
      const c = client();
      expect(await egressSelfCheck({ probe, kubernetesHost: '10.0.0.1' })(submit(mode), c as never)).toBeNull();
      expect(c.updateRuntimeMeta).toHaveBeenCalledWith({ self_check: expect.objectContaining({ mode: 'off' }) });
    }
    expect(probe).not.toHaveBeenCalled();
  });

  it.each(['enforce', 'audit', 'off'] as const)('fails the job under %s when the self-check cannot be recorded', async (mode) => {
    const probe = vi.fn(async () => false);
    const c = client();
    c.updateRuntimeMeta.mockRejectedValue(new Error('409 Conflict'));
    const refusal = await egressSelfCheck({ probe, kubernetesHost: '10.0.0.1' })(submit(mode), c as never);
    expect(refusal).toMatchObject({ success: false, error_code: 'self_check_not_recorded', error: expect.stringMatching(/could not record its self-check/) });
  });
});
