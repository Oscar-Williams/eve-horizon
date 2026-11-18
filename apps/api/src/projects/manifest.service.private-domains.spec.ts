import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ManifestService } from './manifest.service';
import type { SecretsService } from '../secrets/secrets.service';

/** In-memory stand-ins: undefined query methods resolve to [] for list-style names, else null. */
const db = vi.hoisted(() => {
  function stub<T extends object>(defined: T): T {
    return new Proxy(defined, {
      get(target, key, receiver) {
        if (typeof key !== 'string' || key in target) return Reflect.get(target, key, receiver);
        const fn = vi.fn(async () => (/^(list|findByProject$|find.*s$)/.test(key) ? [] : null));
        Reflect.set(target, key, fn);
        return fn;
      },
    });
  }
  return {
    stub,
    projects: stub({ findById: vi.fn(async (id: string) => ({ id, org_id: 'org_a', slug: 'shop', auth_config: null })) }),
    manifests: stub({
      create: vi.fn(async (row: Record<string, unknown>) => ({ ...row, created_at: new Date(), updated_at: new Date() })),
    }),
  };
});

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    projectQueries: vi.fn(() => db.projects),
    orgQueries: vi.fn(() => db.stub({})),
    membershipQueries: vi.fn(() => db.stub({})),
    projectManifestQueries: vi.fn(() => db.manifests),
    agentConfigQueries: vi.fn(() => db.stub({})),
    environmentQueries: vi.fn(() => db.stub({
      findByProjectAndName: vi.fn(async (_projectId: string, name: string) => ({ id: `env_${name}`, name })),
    })),
    ingressAliasQueries: vi.fn(() => db.stub({})),
    customDomainQueries: vi.fn(() => db.stub({
      claimOrUpdate: vi.fn(async (row: Record<string, unknown>) => row),
    })),
    appLinkGrantQueries: vi.fn(() => db.stub({})),
    appLinkSubscriptionQueries: vi.fn(() => db.stub({})),
  };
});

async function warnings(manifest: Record<string, unknown>): Promise<string[]> {
  const service = new ManifestService(
    { begin: async (fn: (tx: unknown) => Promise<unknown>) => fn({}) } as never,
    {} as SecretsService,
  );
  const response = await (service.syncManifest as (...args: unknown[]) => Promise<{ warnings?: string[] }>)(
    'proj_shop',
    { yaml: JSON.stringify({ schema: 'eve/compose/v2', ...manifest }) },
    { user_id: 'user_alice' },
  );
  return response.warnings ?? [];
}

describe('ManifestService.syncManifest: custom domains on a private service', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  });

  it('warns about domains on a service whose ingress is not public', async () => {
    const result = await warnings({
      services: { web: { image: 'web:1', ports: [3000], 'x-eve': { ingress: { port: 3000, domains: ['shop.example.com'] } } } },
    });
    expect(result.join('\n')).toMatch(/shop\.example\.com.*web.*public: true/);
  });

  it('warns about domains an environment adds to a private service', async () => {
    const result = await warnings({
      services: { web: { image: 'web:1', ports: [3000], 'x-eve': { ingress: { public: false, port: 3000 } } } },
      environments: {
        prod: { overrides: { services: { web: { 'x-eve': { ingress: { domains: ['shop.example.com'] } } } } } },
      },
    });
    expect(result.join('\n')).toMatch(/shop\.example\.com.*environments\.prod.*public: true/);
  });

  it('says nothing for domains on a public service', async () => {
    const result = await warnings({
      services: {
        web: { image: 'web:1', ports: [3000], 'x-eve': { ingress: { public: true, port: 3000, domains: ['shop.example.com'] } } },
      },
      environments: {
        prod: { overrides: { services: { web: { 'x-eve': { ingress: { domains: ['prod.example.com'] } } } } } },
      },
    });
    expect(result.filter((w) => /public: true/.test(w))).toEqual([]);
  });
});
