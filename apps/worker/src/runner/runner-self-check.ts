import { connect } from 'node:net';
import { RunnerApiError, type RunnerApiClient, type RunnerResultReport, type RunnerSubmit } from '@eve/shared';

export const RUNNER_SELF_CHECK = 'RUNNER_SELF_CHECK';

/** Runs before the job's token is used; returns a failed result to refuse the job. */
export type RunnerSelfCheck = (submit: RunnerSubmit, client: Pick<RunnerApiClient, 'updateRuntimeMeta'>) => Promise<RunnerResultReport | null>;

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
 * The result goes to the attempt's runtime_meta.self_check, which the API
 * takes once. It is always written before job code starts, `off` (or no
 * mode) included, so job code, which holds the same token, finds the slot
 * taken; when the write fails the job does not run. A network error or a 5xx
 * is retried once; a 409 on that retry means the first write landed (job
 * code cannot have run yet), so it counts as recorded. Under `enforce` (the
 * project's strict profile) a connection that opens fails the job with
 * "egress policy not enforced"; under `audit` the job runs; `off` skips the
 * connections.
 */
export function egressSelfCheck(opts: {
  probe?: (host: string, port: number) => Promise<boolean>;
  kubernetesHost?: string;
  /** Wait before the one retry of the write. */
  retryDelayMs?: number;
} = {}): RunnerSelfCheck {
  const probe = opts.probe ?? tcpReachable;
  const retryDelayMs = opts.retryDelayMs ?? 1000;
  const record = async (client: Pick<RunnerApiClient, 'updateRuntimeMeta'>, report: Record<string, unknown>) => {
    try {
      await client.updateRuntimeMeta({ self_check: report });
    } catch (err) {
      // A refusal (4xx) is final, a 409 on the first write included: something else wrote the slot.
      if (err instanceof RunnerApiError && err.status < 500) throw err;
      console.warn(`[runner] Recording the self-check failed (${err instanceof Error ? err.message : String(err)}); retrying once`);
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
      try {
        await client.updateRuntimeMeta({ self_check: report });
      } catch (retryErr) {
        // The first write reached the API after all; no job code has run to take the slot.
        if (retryErr instanceof RunnerApiError && retryErr.status === 409) return;
        throw retryErr;
      }
    }
  };
  return async (submit, client) => {
    const mode = submit.self_check ?? 'off';
    let metadata = false;
    let kubernetes = false;
    if (mode !== 'off') {
      const kubernetesHost = opts.kubernetesHost ?? process.env.KUBERNETES_SERVICE_HOST ?? 'kubernetes.default.svc';
      [metadata, kubernetes] = await Promise.all([probe(METADATA_HOST, 80), probe(kubernetesHost, 443)]);
    }
    const checkedAt = new Date().toISOString();
    const report = mode === 'off'
      ? { mode, checked_at: checkedAt }
      : { mode, metadata_reachable: metadata, kubernetes_reachable: kubernetes, checked_at: checkedAt };
    try {
      await record(client, report);
    } catch (err) {
      const reason = err instanceof Error ? err.message : String(err);
      console.error(`[runner] Failed to record the self-check: ${reason}`);
      return {
        success: false,
        exit_code: 1,
        error_code: 'self_check_not_recorded',
        error: `The runner could not record its self-check (${reason}), so the job did not run.`,
      };
    }
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
