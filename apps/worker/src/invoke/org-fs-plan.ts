import { normalizeOrgFsMountSpec } from '@eve/shared';

/**
 * The org filesystem volume a runner pod gets for a job's `orgfs_mount`
 * spec: none when the computed mode is `none`, read-only unless the spec
 * writes. Under the project's strict isolation.runner_mode, none at all until
 * each org has its own filesystem. This narrows the mount; it does not
 * isolate one org's files from another's.
 */
export function orgFsPodMount(rawSpec: unknown, opts: { strict?: boolean } = {}): { readOnly: boolean } | null {
  if (opts.strict) return null;
  const spec = normalizeOrgFsMountSpec(rawSpec);
  if (spec.mode === 'none') return null;
  return { readOnly: spec.mode !== 'write' };
}
