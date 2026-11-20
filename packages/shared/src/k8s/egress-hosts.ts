/**
 * egress.allow_hosts: the internet hosts a project's pods may reach, as the
 * manifest declares them (`x-eve.egress.hosts`, at project level and on each
 * service). An entry is an exact host name or a `*.` pattern one label deep
 * (GKE's FQDNNetworkPolicy matches a pattern's `*` against one label), on one
 * TCP port, 443 by default:
 *
 *   hosts:
 *     - api.example.com
 *     - "*.cdn.example.com"
 *     - { name: smtp.example.com, port: 587 }
 *
 * Refused: schemes, paths, ports inside the string, a bare `*`, wildcards
 * anywhere but the first label or over a single label (`*.com`), IP
 * addresses (an FQDN policy matches names), single-label and cluster service
 * names (in-cluster peers are allowed by the NetworkPolicies).
 */

/** At most this many entries in one list (GKE resolves at most 50 addresses per policy). */
export const EGRESS_HOSTS_MAX = 50;
export const EGRESS_DEFAULT_PORT = 443;

/** A host in canonical form: lower case, exactly one of `name` and `pattern`, a port. */
export interface EgressHost {
  name?: string;
  pattern?: string;
  port: number;
}

/** What the manifest may hold: a string, or the object form. */
export type EgressHostEntry = string | { name?: string; pattern?: string; port?: number };

const LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const CLUSTER_SUFFIXES = ['.cluster.local', '.svc', '.local', '.localhost', '.internal'];

function nameProblem(name: string): string | null {
  if (name.length > 253) return 'is longer than 253 characters';
  if (name.includes('://')) return 'has a scheme; give the host name only';
  if (name.includes('/')) return 'has a path; give the host name only';
  if (name.includes(':')) {
    return /^[0-9a-f:.]+$/i.test(name) && name.split(':').length > 2
      ? 'is an IP address; allow lists name hosts'
      : 'has a port; use { name, port }';
  }
  if (/^[0-9.]+$/.test(name)) return 'is an IP address; allow lists name hosts';
  const labels = name.split('.');
  if (labels.length < 2) return 'is a single label; give a fully qualified host name';
  if (!labels.every((label) => LABEL.test(label))) return 'is not a valid host name';
  if (CLUSTER_SUFFIXES.some((suffix) => name.endsWith(suffix))) {
    return 'is a cluster or local name; in-cluster peers need no allow list entry';
  }
  return null;
}

function patternProblem(pattern: string): string | null {
  if (!pattern.startsWith('*.')) return 'a pattern starts with "*." (one label deep)';
  const rest = pattern.slice(2);
  if (rest.includes('*')) return 'a pattern has one "*", as its first label';
  if (rest.split('.').length < 2) return 'a pattern must sit under a domain, not a top-level domain';
  return nameProblem(rest);
}

function portProblem(port: unknown): string | null {
  if (port === undefined) return null;
  return typeof port === 'number' && Number.isInteger(port) && port >= 1 && port <= 65535
    ? null
    : 'port must be an integer from 1 to 65535';
}

/** Why an entry is refused, or null when it is valid. */
export function egressHostProblem(entry: unknown): string | null {
  if (typeof entry === 'string') {
    const value = entry.trim().toLowerCase();
    if (value === '*' || value === '') return 'a bare "*" or empty entry would allow every host';
    const problem = value.includes('*') ? patternProblem(value) : nameProblem(value);
    return problem ? `"${entry}": ${problem}` : null;
  }
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
    return 'an entry is a host name, a "*." pattern, or { name | pattern, port }';
  }
  const record = entry as Record<string, unknown>;
  const unknown = Object.keys(record).filter((key) => !['name', 'pattern', 'port'].includes(key));
  if (unknown.length > 0) return `unknown field(s) ${unknown.join(', ')}; an entry takes name or pattern, and port`;
  const port = portProblem(record.port);
  if (port) return port;
  const hasName = record.name !== undefined;
  const hasPattern = record.pattern !== undefined;
  if (hasName === hasPattern) return 'an entry takes exactly one of name and pattern';
  const value = hasName ? record.name : record.pattern;
  if (typeof value !== 'string') return 'name and pattern are strings';
  const lower = value.trim().toLowerCase();
  const problem = hasName
    ? (lower.includes('*') ? 'a name has no "*"; use pattern' : nameProblem(lower))
    : patternProblem(lower);
  return problem ? `"${value}": ${problem}` : null;
}

/** An entry in canonical form, or null when it is refused. */
export function parseEgressHost(entry: unknown): EgressHost | null {
  if (egressHostProblem(entry) !== null) return null;
  if (typeof entry === 'string') {
    const value = entry.trim().toLowerCase();
    return value.startsWith('*.')
      ? { pattern: value, port: EGRESS_DEFAULT_PORT }
      : { name: value, port: EGRESS_DEFAULT_PORT };
  }
  const record = entry as { name?: string; pattern?: string; port?: number };
  const port = record.port ?? EGRESS_DEFAULT_PORT;
  return record.name !== undefined
    ? { name: record.name.trim().toLowerCase(), port }
    : { pattern: record.pattern!.trim().toLowerCase(), port };
}

/** `name:port` or `*.pattern:port`. */
export function egressHostKey(host: EgressHost): string {
  return `${host.name ?? host.pattern}:${host.port}`;
}

/** Valid entries in canonical form, first occurrence kept; invalid ones dropped. */
export function canonicalEgressHosts(entries: readonly unknown[] | null | undefined): EgressHost[] {
  const seen = new Set<string>();
  const out: EgressHost[] = [];
  for (const entry of entries ?? []) {
    const host = parseEgressHost(entry);
    if (!host || seen.has(egressHostKey(host))) continue;
    seen.add(egressHostKey(host));
    out.push(host);
  }
  return out;
}

/**
 * The host (and port) a runner clones from: HTTPS (443), HTTP (80),
 * `ssh://` (its port, else 22) and scp-style `git@host:path` (22). Local
 * paths, `file://` and IP addresses give null.
 */
export function gitEgressHost(repoUrl: string | null | undefined): EgressHost | null {
  const raw = repoUrl?.trim();
  if (!raw) return null;
  let host: string;
  let port: number;
  const scp = /^[^@/\s]+@([^:/\s]+):(?!\/)/.exec(raw);
  if (scp) {
    host = scp[1];
    port = 22;
  } else {
    let url: URL;
    try {
      url = new URL(raw);
    } catch {
      return null;
    }
    const defaults: Record<string, number> = { 'https:': 443, 'http:': 80, 'ssh:': 22, 'git+ssh:': 22 };
    if (!(url.protocol in defaults)) return null;
    host = url.hostname;
    port = url.port ? Number(url.port) : defaults[url.protocol];
  }
  return parseEgressHost({ name: host, port });
}

/** The lists a manifest declares: the project's, and each service's that has one. */
export interface ManifestEgressHosts {
  project: EgressHost[];
  services: Record<string, EgressHost[]>;
}

function xeve(value: unknown): Record<string, unknown> | null {
  if (!value || typeof value !== 'object') return null;
  const record = value as Record<string, unknown>;
  const ext = record['x-eve'] ?? record.x_eve;
  return ext && typeof ext === 'object' ? ext as Record<string, unknown> : null;
}

function hostList(ext: Record<string, unknown> | null): EgressHost[] {
  const egress = ext?.egress as { hosts?: unknown } | undefined;
  return Array.isArray(egress?.hosts) ? canonicalEgressHosts(egress!.hosts as unknown[]) : [];
}

/** Read `x-eve.egress.hosts` at project level and on each service of a parsed manifest. */
export function manifestEgressHosts(manifest: unknown): ManifestEgressHosts {
  const services: Record<string, EgressHost[]> = {};
  const declared = (manifest as { services?: Record<string, unknown> } | null)?.services;
  for (const [name, service] of Object.entries(declared && typeof declared === 'object' ? declared : {})) {
    const list = hostList(xeve(service));
    if (list.length > 0) services[name] = list;
  }
  return { project: hostList(xeve(manifest)), services };
}
