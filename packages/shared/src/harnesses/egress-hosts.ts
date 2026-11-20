import { canonicalEgressHosts, type EgressHost } from '../k8s/egress-hosts.js';
import { harnessAdapters, resolveHarnessAdapter } from './adapters/index.js';
import type { HarnessAdapter } from './adapters/types.js';
import type { HarnessName } from './registry.js';

/**
 * The default egress hosts of the named harnesses (aliases accepted, unknown
 * names ignored), or of every harness when none are named, each once.
 */
export function harnessEgressHosts(names?: readonly string[]): EgressHost[] {
  const adapters = names
    ? names.map((name) => resolveHarnessAdapter(name.trim().toLowerCase() as HarnessName)).filter((a): a is HarnessAdapter => a !== undefined)
    : harnessAdapters;
  return canonicalEgressHosts(adapters.flatMap((adapter) => adapter.egressHosts));
}
