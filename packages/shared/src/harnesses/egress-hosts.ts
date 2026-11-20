import { canonicalEgressHosts, type EgressHost } from '../k8s/egress-hosts.js';
import { harnessAdapters, resolveHarnessAdapter } from './adapters/index.js';
import type { HarnessAdapter } from './adapters/types.js';
import { getHarnessAuthStatus } from './auth.js';
import { HARNESS_CANONICAL_NAMES, resolveHarnessName, type HarnessCanonicalName, type HarnessName } from './registry.js';

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

/**
 * The harnesses a project's harness profiles name (`x-eve.agents.profiles`,
 * every target of every profile, fallbacks included), canonical, each once.
 * Unknown names are ignored.
 */
export function profileHarnesses(profiles: Record<string, unknown> | null | undefined): HarnessCanonicalName[] {
  const names = new Set<HarnessCanonicalName>();
  for (const targets of Object.values(profiles ?? {})) {
    for (const target of Array.isArray(targets) ? targets : []) {
      const harness = (target as { harness?: unknown } | null)?.harness;
      const canonical = typeof harness === 'string' ? resolveHarnessName(harness.trim().toLowerCase()) : undefined;
      if (canonical) names.add(canonical);
    }
  }
  return [...names];
}

/**
 * The harnesses these secret names are, on their own, credentials for.
 * `pi` is left out: it runs on any provider's key, and its hosts are those
 * providers' APIs, which the provider's own harness already lists.
 */
export function credentialHarnesses(secretKeys: readonly string[]): HarnessCanonicalName[] {
  const env = Object.fromEntries(secretKeys.map((key) => [key, 'set']));
  return HARNESS_CANONICAL_NAMES
    .filter((name) => name !== 'pi')
    .filter((name) => getHarnessAuthStatus(name, env, { hostCredentials: false }).available);
}
