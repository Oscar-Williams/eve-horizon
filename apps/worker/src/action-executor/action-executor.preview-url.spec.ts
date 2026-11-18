import { beforeEach, describe, expect, it, vi } from 'vitest';
import yaml from 'yaml';
import { ActionExecutorService } from './action-executor.service.js';

const mocks = vi.hoisted(() => ({
  profile: 'legacy' as 'legacy' | 'audit' | 'strict',
  governing: vi.fn(),
  decide: vi.fn(),
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  governingSecurityProfile: mocks.governing,
  decideSecurityRule: mocks.decide,
}));

vi.mock('@eve/shared', async (importOriginal) => {
  const actual = await importOriginal() as Record<string, unknown>;
  return { ...actual, loadConfig: () => ({ EVE_DEFAULT_DOMAIN: 'apps.test' }) };
});

function service(services: Record<string, unknown>) {
  const executor = new ActionExecutorService(null as any, {} as any, {} as any);
  Object.assign(executor as unknown as Record<string, unknown>, {
    projects: { findById: vi.fn().mockResolvedValue({ id: 'proj_shop', slug: 'shop', org_id: 'org_acme' }) },
    releases: { findById: vi.fn().mockResolvedValue({ id: 'rel_1', manifest_hash: 'h1' }) },
    manifests: { findByProjectAndHash: vi.fn().mockResolvedValue({ manifest_yaml: yaml.stringify({ services }) }) },
    orgs: { findById: vi.fn().mockResolvedValue({ id: 'org_acme', slug: 'acme' }) },
  });
  return (executor as any).computePreviewUrl('proj_shop', 'rel_1', 'prod') as Promise<string | null>;
}

beforeEach(() => {
  vi.clearAllMocks();
  mocks.profile = 'legacy';
  mocks.governing.mockImplementation(async () => mocks.profile);
  mocks.decide.mockImplementation(async () => mocks.profile);
});

describe('ActionExecutorService preview URL follows the deployer', () => {
  it('names no URL for a service with ports and no ingress block under strict', async () => {
    mocks.profile = 'strict';
    await expect(service({ web: { image: 'web:1', ports: [3000] } })).resolves.toBeNull();
  });

  it('names that service under audit and legacy', async () => {
    mocks.profile = 'audit';
    await expect(service({ web: { image: 'web:1', ports: [3000] } })).resolves.toBe('https://web.acme-shop-prod.apps.test');
  });

  it('names no URL for an ingress block that does not say public: true', async () => {
    await expect(service({ web: { image: 'web:1', ports: [3000], 'x-eve': { ingress: { port: 3000 } } } }))
      .resolves.toBeNull();
  });

  it('names a declared public service and records nothing', async () => {
    mocks.profile = 'strict';
    await expect(service({
      worker: { image: 'w:1', ports: [9000], 'x-eve': { ingress: { public: false } } },
      app: { image: 'app:1', ports: [3000], 'x-eve': { ingress: { public: true, port: 3000 } } },
    })).resolves.toBe('https://app.acme-shop-prod.apps.test');
    expect(mocks.decide).not.toHaveBeenCalled();
  });
});
