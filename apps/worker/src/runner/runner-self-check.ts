import { connect } from 'node:net';
import type { RunnerApiClient, RunnerResultReport, RunnerSubmit } from '@eve/shared';

export const RUNNER_SELF_CHECK = 'RUNNER_SELF_CHECK';

/** Runs before the job's token is used; returns a failed result to refuse the job. */
export type RunnerSelfCheck = (submit: RunnerSubmit, client: Pick<RunnerApiClient, 'updateRuntimeMeta'>) => Promise<RunnerResultReport | null>;

/** No self-check: the runner takes every authenticated submit. */
export const noSelfCheck: RunnerSelfCheck = async () => null;

const METADATA_HOST = '169.254.169.254';

/** Whether a TCP connection to host:port opens within the timeout. */
export function tcpReachable(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = connect({ host, port });
    const done = (reachable: boolean) => { socket.destroy(); resolve(reachable); };
    socket.setTimeout(timeoutMs, () => done(false));
    socket.once('connect', () => done(true));
    socket.once('error', () => done(false));
  });
}

/**
 * The runner's egress self-check (rule isolation.runner_mode). Before the job
 * token is used, the runner opens TCP connections to the metadata server
 * (169.254.169.254:80) and the Kubernetes API (KUBERNETES_SERVICE_HOST:443).
 * The result goes to the attempt's runtime_meta.self_check. Under `enforce`
 * (the project's strict profile) a connection that opens fails the job with
 * "egress policy not enforced"; under `audit` the job runs; `off` (or no mode)
 * skips the check.
 */
export function egressSelfCheck(opts: {
  probe?: (host: string, port: number) => Promise<boolean>;
  kubernetesHost?: string;
} = {}): RunnerSelfCheck {
  const probe = opts.probe ?? tcpReachable;
  return async (submit, client) => {
    const mode = submit.self_check ?? 'off';
    if (mode === 'off') return null;
    const kubernetesHost = opts.kubernetesHost ?? process.env.KUBERNETES_SERVICE_HOST ?? 'kubernetes.default.svc';
    const [metadata, kubernetes] = await Promise.all([probe(METADATA_HOST, 80), probe(kubernetesHost, 443)]);
    const report = { mode, metadata_reachable: metadata, kubernetes_reachable: kubernetes, checked_at: new Date().toISOString() };
    await client.updateRuntimeMeta({ self_check: report }).catch((err) => {
      console.error(`[runner] Failed to report the self-check: ${err instanceof Error ? err.message : String(err)}`);
    });
    if (mode !== 'enforce' || (!metadata && !kubernetes)) return null;
    const reachable = [metadata ? 'the metadata server' : null, kubernetes ? 'the Kubernetes API' : null].filter(Boolean).join(' and ');
    return {
      success: false,
      exit_code: 1,
      error_code: 'egress_not_enforced',
      error: `egress policy not enforced: this runner pod can reach ${reachable}. The job did not run.`,
    };
  };
}
