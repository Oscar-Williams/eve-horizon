/**
 * The dispatch hook for egress.default_deny: before a runner pod starts, the
 * project's runner policies are brought in line with its profile, so a
 * claimed pod meets its project's allow (or, under `audit` and `legacy`, the
 * allow-all companion) the moment it carries the project label.
 *
 * The worker's NetworkModule registers the live instance at startup; until
 * then (and in unit tests that build services directly) the hook does
 * nothing. It fails the job for egress.allow_hosts at `strict` with no
 * provider, and for a project under either strict egress rule whose runner
 * policies could not be written (the pod would meet an older, possibly
 * wider set). Under `audit` and `legacy` a failure is logged and the job
 * goes on: the static `eve-runner-deny` still holds it to DNS and the API
 * where no project set exists.
 */

export interface RunnerEgress {
  ensureRunnersForDispatch(projectId: string): Promise<unknown>;
}

let registered: RunnerEgress | null = null;

export function registerRunnerEgress(egress: RunnerEgress | null): void {
  registered = egress;
}

/** Errors that refuse the job rather than being logged. */
const REFUSALS = new Set(['EgressProviderMissingError', 'RunnerEgressSyncError']);

/**
 * Returns the refusal when the job must not run: egress.allow_hosts is
 * `strict` and no provider can allow its hosts (EgressProviderMissingError),
 * or a strict project's runner policies could not be written
 * (RunnerEgressSyncError). Any other failure is logged and the job goes on.
 */
export async function ensureRunnerEgress(projectId: string | null | undefined): Promise<string | undefined> {
  if (!registered || !projectId) return undefined;
  try {
    await registered.ensureRunnersForDispatch(projectId);
  } catch (error) {
    if (error instanceof Error && REFUSALS.has(error.name)) return error.message;
    console.warn(
      `[runner-egress] Could not bring the runner egress policies of project ${projectId} in line with its profile: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return undefined;
}
