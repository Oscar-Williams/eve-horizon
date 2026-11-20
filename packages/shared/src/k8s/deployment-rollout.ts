/** The fields of a Deployment that say whether its rollout is done. */
export interface DeploymentRolloutFields {
  metadata?: { name?: string; generation?: number };
  spec?: { replicas?: number };
  status?: {
    observedGeneration?: number;
    replicas?: number;
    updatedReplicas?: number;
    availableReplicas?: number;
  };
}

/**
 * Whether a Deployment's rollout is done, as `kubectl rollout status` judges
 * it: the controller has seen the latest spec, every desired pod runs that
 * spec and is available, and no pod of an older ReplicaSet is left. Right
 * after an apply the old pods are still available; they never make a
 * Deployment ready. One scaled to zero is ready.
 */
export function isDeploymentRolledOut(deployment: DeploymentRolloutFields): boolean {
  const desired = deployment.spec?.replicas ?? 0;
  if (desired === 0) return true;
  const status = deployment.status ?? {};
  const updated = status.updatedReplicas ?? 0;
  return (status.observedGeneration ?? 0) >= (deployment.metadata?.generation ?? 0)
    && updated >= desired
    && (status.replicas ?? 0) <= updated
    && (status.availableReplicas ?? 0) >= desired;
}
