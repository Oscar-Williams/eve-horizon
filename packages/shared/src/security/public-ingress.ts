import type { SecurityProfile } from './profile.js';

/** A service's `x-eve.ingress` block, if it declares one. */
export function serviceIngressBlock(service: unknown): Record<string, unknown> | null {
  const fields = service && typeof service === 'object' ? service as Record<string, unknown> : null;
  const xeve = (fields?.['x-eve'] ?? fields?.x_eve) as Record<string, unknown> | undefined;
  const ingress = xeve && typeof xeve === 'object' ? xeve.ingress : undefined;
  return ingress && typeof ingress === 'object' && !Array.isArray(ingress)
    ? ingress as Record<string, unknown>
    : null;
}

function listsPorts(service: unknown): boolean {
  const ports = service && typeof service === 'object' ? (service as Record<string, unknown>).ports : undefined;
  return Array.isArray(ports) && ports.length > 0;
}

/**
 * A service that would be public only because it lists ports and declares no
 * `x-eve.ingress` block: the case the `ports.implicit_public` rule governs.
 */
export function isImplicitPublicIngress(service: unknown): boolean {
  return !serviceIngressBlock(service) && listsPorts(service);
}

/**
 * Whether a service gets a public HTTP ingress. An `x-eve.ingress` block
 * decides by `public: true`. With no block, a service that lists ports is
 * public, except under the project's `strict` profile. The deployer, preview
 * URLs and `env diagnose` all use this rule.
 */
export function isPublicIngress(service: unknown, profile: SecurityProfile): boolean {
  const ingress = serviceIngressBlock(service);
  if (ingress) return ingress.public === true;
  return listsPorts(service) && profile !== 'strict';
}
