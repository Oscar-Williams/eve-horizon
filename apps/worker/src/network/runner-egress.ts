/**
 * The dispatch hook for egress.default_deny: before a runner pod starts, the
 * project's runner policies are brought in line with its profile, so a
 * claimed pod meets its project's allow (or, under `audit` and `legacy`, the
 * allow-all companion) the moment it carries the project label.
 *
 * The worker's NetworkModule registers the live instance at startup; until
 * then (and in unit tests that build services directly) the hook does
 * nothing. It never fails the job: the static `eve-runner-deny` holds
 * whatever happens here, so a failure costs the job its extras, never
 * isolation.
 */
export interface RunnerEgress {
  ensureRunnersForDispatch(projectId: string): Promise<unknown>;
}

let registered: RunnerEgress | null = null;

export function registerRunnerEgress(egress: RunnerEgress | null): void {
  registered = egress;
}

export async function ensureRunnerEgress(projectId: string | null | undefined): Promise<void> {
  if (!registered || !projectId) return;
  try {
    await registered.ensureRunnersForDispatch(projectId);
  } catch (error) {
    console.warn(
      `[runner-egress] Could not bring the runner egress policies of project ${projectId} in line with its profile: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
