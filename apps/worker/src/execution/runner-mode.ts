import type { RunnerModeDecision } from '@eve/db';

/**
 * Rule isolation.runner_mode in the worker. Job code (agent jobs, script
 * steps, `action: run`) runs in a credential-free runner pod under the
 * project's strict profile, or whenever the instance sets
 * EVE_RUNNER_PODS_ONLY. Outside Kubernetes there are no runner pods, so such
 * work fails rather than running in the worker's own process.
 */
export function inKubernetes(): boolean {
  return process.env.EVE_RUNTIME === 'k8s';
}

export function strictNeedsRunnerPods(kind: string): Error {
  return new Error(`isolation.runner_mode: strict needs runner pods; this ${kind} would run in the worker's own process `
    + '(EVE_RUNTIME is not k8s). Run the instance on Kubernetes, or set the project to audit.');
}

/** The runner's egress self-check mode for a decision: enforce under strict, audit under audit or the switch. */
export function runnerSelfCheckMode(mode: RunnerModeDecision): 'enforce' | 'audit' | 'off' {
  if (mode.profile === 'strict') return 'enforce';
  if (mode.profile === 'audit' || mode.podsOnly) return 'audit';
  return 'off';
}
