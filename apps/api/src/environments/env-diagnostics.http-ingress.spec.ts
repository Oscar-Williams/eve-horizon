import { describe, expect, it, vi } from 'vitest';
import yaml from 'yaml';
import type { SecurityProfile } from '@eve/shared';
import { EnvDiagnosticsService } from './env-diagnostics.service';

vi.mock('@eve/shared', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return { ...actual, loadConfig: () => ({ EVE_DEFAULT_DOMAIN: 'apps.test', EVE_DEFAULT_INGRESS_CLASS: 'nginx' }) };
});

async function listed(profile: SecurityProfile, services: Record<string, unknown>): Promise<string[]> {
  const diagnostics = Object.create(EnvDiagnosticsService.prototype) as Record<string, unknown>;
  const effectiveProfile = vi.fn(async () => profile);
  Object.assign(diagnostics, {
    security: { effectiveProfile },
    manifests: { findLatestByProject: vi.fn().mockResolvedValue({ manifest_yaml: yaml.stringify({ services }) }) },
    projects: { findById: vi.fn().mockResolvedValue({ id: 'proj_shop', slug: 'shop', org_id: 'org_acme' }) },
    orgs: { findById: vi.fn().mockResolvedValue({ id: 'org_acme', slug: 'acme' }) },
    k8sAvailable: false,
  });
  const rows = await (diagnostics as unknown as {
    listHttpIngress(p: string, e: string, n: string, w: string[]): Promise<Array<{ service: string }>>;
  }).listHttpIngress('proj_shop', 'prod', 'eve-acme-shop-prod', []);
  return rows.map((row) => row.service).sort();
}

const SERVICES = {
  web: { image: 'web:1', ports: [3000] },
  app: { image: 'app:1', ports: [3000], 'x-eve': { ingress: { public: true, port: 3000 } } },
  api: { image: 'api:1', ports: [8080], 'x-eve': { ingress: { port: 8080 } } },
};

describe('env diagnose HTTP ingress follows the deployer', () => {
  it('leaves out a service with ports and no ingress block under strict', async () => {
    expect(await listed('strict', SERVICES)).toEqual(['app']);
  });

  it('lists it under audit', async () => {
    expect(await listed('audit', SERVICES)).toEqual(['app', 'web']);
  });
});
