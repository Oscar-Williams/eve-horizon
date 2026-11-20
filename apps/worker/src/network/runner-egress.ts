/**
 * The dispatch hook for egress.default_deny: before a runner pod starts, the
 * project's runner policies are brought in line with its profile, so a
 * claimed pod meets its project's allow (or, under `audit` and `legacy`, the
 * allow-all companion) the moment it carries the project label.
 *
 * The worker's NetworkModule registers the live instance at startup; until
 * then (and in unit tests that build services directly) the hook does
 * nothing. It fails the job only for egress.allow_hosts at `strict` with no
 * provider; otherwise the static `eve-runner-deny` holds whatever happens
 * here, so a failure costs the job its extras, never isolation.
 */

export interface RunnerEgress {
  ensureRunnersForDispatch(projectId: string): Promise<unknown>;
}

let registered: RunnerEgress | null = null;

export function registerRunnerEgress(egress: RunnerEgress | null): void {
  registered = egress;
}

/**
 * Returns the refusal when the job must not run: egress.allow_hosts is
 * `strict` and no provider can allow its hosts (EgressProviderMissingError).
 * Any other failure is logged and the job goes on.
 */
export async function ensureRunnerEgress(projectId: string | null | undefined): Promise<string | undefined> {
  if (!registered || !projectId) return undefined;
  try {
    await registered.ensureRunnersForDispatch(projectId);
  } catch (error) {
    if (error instanceof Error && error.name === 'EgressProviderMissingError') return error.message;
    console.warn(
      `[runner-egress] Could not bring the runner egress policies of project ${projectId} in line with its profile: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }
  return undefined;
}
