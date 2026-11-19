import { normalizeOrgFsMountSpec } from '@eve/shared';

/**
 * The org filesystem volume a runner pod gets for a job's `orgfs_mount`
 * spec: none when the computed mode is `none`, read-only unless the spec
 * writes. This narrows the mount; it does not isolate one org's files from
 * another's (that waits for an org filesystem per org).
 */
export function orgFsPodMount(rawSpec: unknown): { readOnly: boolean } | null {
  const spec = normalizeOrgFsMountSpec(rawSpec);
  if (spec.mode === 'none') return null;
  return { readOnly: spec.mode !== 'write' };
}
