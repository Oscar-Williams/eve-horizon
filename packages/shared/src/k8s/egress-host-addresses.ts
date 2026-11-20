/**
 * egress.allow_hosts at manifest sync: what the declared exact host names
 * resolve to. A GKE FQDN policy allows whatever addresses a name resolves
 * to, so a name pointing inside the cluster or a private network would open
 * that address to the project's pods. Each name is resolved once; one with
 * any answer outside the public internet (private, CGNAT, link-local,
 * loopback, other reserved ranges, `EVE_CLUSTER_PRIVATE_CIDRS`, and the
 * instance's `network.private_cidrs`) is refused.
 *
 * DNS can change after the sync: the check stops a mistake or a naive
 * attempt, not an owner of the name's DNS. Patterns cannot be resolved and
 * are not checked (names under wildcard DNS services are refused by
 * egress-hosts.ts). A name that does not resolve yet passes.
 */
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { isPublicAddress } from '../net/outbound-url.js';
import type { EgressHost } from './egress-hosts.js';

export interface EgressHostAddressOptions {
  /** More IPv4 CIDRs that are private here (the instance's `network.private_cidrs`). */
  privateCidrs?: readonly string[];
  /** Every address a name resolves to (default: the system resolver, both families). */
  resolve?: (host: string) => Promise<string[]>;
}

async function systemResolve(host: string): Promise<string[]> {
  return (await lookup(host, { all: true, verbatim: true })).map((entry) => entry.address);
}

/** One message per declared name that resolves to a non-public address; empty when none does. */
export async function egressHostAddressProblems(
  hosts: readonly EgressHost[],
  options: EgressHostAddressOptions = {},
): Promise<string[]> {
  const resolve = options.resolve ?? systemResolve;
  const extra = new BlockList();
  for (const cidr of options.privateCidrs ?? []) {
    const [network, prefix] = cidr.split('/');
    if (isIP(network) === 4 && Number.isInteger(Number(prefix))) extra.addSubnet(network, Number(prefix), 'ipv4');
  }
  const names = [...new Set(hosts.map((host) => host.name).filter((name): name is string => Boolean(name)))];
  const problems: string[] = [];
  for (const name of names) {
    let addresses: string[];
    try {
      addresses = await resolve(name);
    } catch {
      continue;
    }
    const blocked = addresses.filter((address) => {
      const family = isIP(address);
      if (family === 0) return false;
      return !isPublicAddress(address) || (family === 4 && extra.check(address, 'ipv4'));
    });
    if (blocked.length > 0) {
      problems.push(`"${name}" resolves to ${blocked.join(', ')}, which is not a public internet address`);
    }
  }
  return problems;
}
