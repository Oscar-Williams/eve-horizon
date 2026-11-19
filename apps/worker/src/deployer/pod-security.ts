import type * as k8s from '@kubernetes/client-node';
import type { ServiceSecurity } from '@eve/shared';

/**
 * Rule `isolation.pod_security` (project). Under `strict` tenant pods and
 * service job pods run with the restricted Pod Security context and a numeric
 * user; under `audit` each service is recorded with what strict would do.
 */
export const POD_SECURITY_RULE = 'isolation.pod_security';

/** What an image's config says about the user its process runs as. */
export interface ImageUser {
  /** `root` (root or uid 0), `empty` (no USER: root), `numeric`, `name`, or `unknown` (not read). */
  kind: 'root' | 'empty' | 'numeric' | 'name' | 'unknown';
  /** The image's `USER` as written, when read. */
  raw?: string;
  uid?: number;
  gid?: number;
}

/** Why `strict` refuses a service. */
export type PodSecurityBlocker = 'stable_egress' | 'root_user' | 'named_user' | 'unknown_user';

export type PodSecurityLevel = 'restricted' | 'baseline';

export interface PodSecurityPlan {
  podSecurityContext: k8s.V1PodSecurityContext;
  containerSecurityContext: k8s.V1SecurityContext;
  /** The Pod Security Standard the pod meets: `baseline` once it opts out. */
  level: PodSecurityLevel;
  blocker: PodSecurityBlocker | null;
  /** For the finding: names and numbers only. */
  detail: Record<string, string | number | boolean | null>;
}

/**
 * Read an image config's `User`: `uid`, `uid:gid`, a name, or nothing.
 * Only an all-numeric user (and group, when given) can satisfy
 * `runAsNonRoot`; the kubelet cannot check a name.
 */
export function parseImageUser(raw: string | null | undefined): ImageUser {
  if (raw === null || raw === undefined) return { kind: 'unknown' };
  const value = raw.trim();
  if (value === '') return { kind: 'empty', raw: value };
  const [user, group] = value.split(':', 2);
  const numeric = (part: string | undefined) => (part !== undefined && /^\d+$/.test(part) ? Number(part) : undefined);
  const uid = numeric(user);
  if (user === 'root' || uid === 0) return { kind: 'root', raw: value };
  const gid = numeric(group);
  if (uid === undefined || (group !== undefined && group !== '' && gid === undefined)) {
    return { kind: 'name', raw: value };
  }
  return { kind: 'numeric', raw: value, uid, ...(gid !== undefined ? { gid } : {}) };
}

/**
 * The security context strict gives a service's pod, and whether strict
 * refuses it. The user comes from `x-eve.security.run_as_user` (and
 * `run_as_group`), else from the image's numeric `USER`; with neither, only
 * `run_as_root: true` lets it run. `imageUser` is null when it was not read
 * because the manifest settles the user.
 */
export function planPodSecurity(input: {
  envName: string;
  serviceName: string;
  security: ServiceSecurity | undefined;
  imageUser: ImageUser | null;
  ports: number[];
  stableEgress: boolean;
}): PodSecurityPlan {
  const security = input.security ?? {};
  const image = input.imageUser ?? { kind: 'unknown' as const };
  const runAsRoot = security.run_as_root === true;
  const capabilities = [...new Set(security.capabilities ?? [])];
  const fromManifest = security.run_as_user !== undefined;
  const imageNumeric = image.kind === 'numeric';
  const uid = security.run_as_user ?? (imageNumeric ? image.uid : undefined);
  const gid = security.run_as_group ?? (!fromManifest && imageNumeric ? image.gid : undefined);

  let blocker: PodSecurityBlocker | null = null;
  if (input.stableEgress) {
    blocker = 'stable_egress';
  } else if (!runAsRoot && (uid === undefined || uid === 0)) {
    blocker = uid === 0 || image.kind === 'root' || image.kind === 'empty'
      ? 'root_user'
      : image.kind === 'name' ? 'named_user' : 'unknown_user';
  }

  const containerSecurityContext: k8s.V1SecurityContext = {
    allowPrivilegeEscalation: false,
    capabilities: { drop: ['ALL'], ...(capabilities.length > 0 ? { add: capabilities } : {}) },
    ...(runAsRoot ? {} : { runAsNonRoot: true }),
    ...(uid !== undefined ? { runAsUser: uid } : {}),
    ...(gid !== undefined ? { runAsGroup: gid } : {}),
  };
  // Restricted allows adding back NET_BIND_SERVICE only, and no root user.
  const level: PodSecurityLevel = runAsRoot || capabilities.some((cap) => cap !== 'NET_BIND_SERVICE')
    ? 'baseline'
    : 'restricted';

  const wouldAdd = [
    'seccomp_runtime_default',
    'no_service_account_token',
    'no_privilege_escalation',
    'drop_all_capabilities',
    ...(runAsRoot ? [] : ['run_as_non_root']),
    ...(uid !== undefined ? ['run_as_user'] : []),
    ...(gid !== undefined ? ['run_as_group'] : []),
  ];
  const optOut = [
    ...(runAsRoot ? ['run_as_root'] : []),
    ...(capabilities.length > 0 ? [`capabilities:${capabilities.join('+')}`] : []),
  ];

  return {
    podSecurityContext: { seccompProfile: { type: 'RuntimeDefault' } },
    containerSecurityContext,
    level,
    blocker,
    detail: {
      env: input.envName,
      service: input.serviceName,
      image_user: input.imageUser ? image.kind : 'not_read',
      user: image.raw ?? null,
      uid: uid ?? null,
      uid_source: uid === undefined ? null : fromManifest ? 'manifest' : 'image',
      low_ports: input.ports.filter((port) => port < 1024).join(','),
      would_add: wouldAdd.join(','),
      opt_out: optOut.length > 0 ? optOut.join(',') : null,
      strict_blocker: blocker,
    },
  };
}

/** Whether strict needs the image's user: the manifest does not settle it. */
export function needsImageUser(security: ServiceSecurity | undefined): boolean {
  return security?.run_as_root !== true && security?.run_as_user === undefined;
}

/** Why strict refuses a service, and what to change. */
export function describePodSecurityBlocker(serviceName: string, plan: PodSecurityPlan): string {
  const user = plan.detail.user;
  switch (plan.blocker) {
    case 'stable_egress':
      return `${serviceName}: x-eve.networking.egress: stable runs the pod on the host network; remove it`;
    case 'named_user':
      return `${serviceName}: its image runs as user "${user}", a name the kubelet cannot check; ` +
        'set x-eve.security.run_as_user and run_as_group to its numeric uid and gid, or make the image USER numeric';
    case 'root_user':
      return `${serviceName}: it runs as root; set x-eve.security.run_as_user and run_as_group to a non-root uid and gid, ` +
        'or opt out with x-eve.security.run_as_root: true';
    case 'unknown_user':
      return `${serviceName}: its image config could not be read to find its user; ` +
        'set x-eve.security.run_as_user and run_as_group';
    default:
      return serviceName;
  }
}

/** Apply a strict plan to a pod spec and its containers. */
export function applyPodSecurity(podSpec: Record<string, any>, plan: PodSecurityPlan): void {
  podSpec.automountServiceAccountToken = false;
  podSpec.securityContext = { ...(podSpec.securityContext ?? {}), ...plan.podSecurityContext };
  for (const container of (podSpec.containers ?? []) as Array<Record<string, any>>) {
    container.securityContext = { ...plan.containerSecurityContext };
  }
}

/**
 * Namespace labels at a strict deploy: Pod Security `warn` and `audit` at the
 * namespace's level. Never `enforce`: Eve writes every pod spec, and an
 * enforce label would refuse old ReplicaSet pods when a node is replaced.
 */
export function podSecurityNamespaceLabels(level: PodSecurityLevel): Record<string, string> {
  return {
    'pod-security.kubernetes.io/warn': level,
    'pod-security.kubernetes.io/audit': level,
  };
}
