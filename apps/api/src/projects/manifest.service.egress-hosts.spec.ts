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
    systemSettingsQueries: vi.fn(() => db.stub({
      get: vi.fn(async (key: string) => (key === 'network.private_cidrs' ? { key, value: '34.118.224.0/20' } : null)),
    })),
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

const ANSWERS: Record<string, string[]> = {
  'api.example.com': ['93.184.216.34'],
  'hooks.example.com': ['93.184.216.35'],
  'db.example.com': ['10.20.0.5'],
  'svc.example.com': ['34.118.224.10'],
};

async function sync(egress: Record<string, unknown>, services: Record<string, unknown> = { web: { image: 'web:1' } }) {
  const service = new ManifestService(
    { begin: async (fn: (tx: unknown) => Promise<unknown>) => fn({}) } as never,
    {} as SecretsService,
  );
  const lookups: string[] = [];
  (service as unknown as { resolveHost: (host: string) => Promise<string[]> }).resolveHost = async (host: string) => {
    lookups.push(host);
    if (!(host in ANSWERS)) throw Object.assign(new Error(`getaddrinfo ENOTFOUND ${host}`), { code: 'ENOTFOUND' });
    return ANSWERS[host];
  };
  const run = (service.syncManifest as (...args: unknown[]) => Promise<unknown>)(
    'proj_shop',
    { yaml: JSON.stringify({ schema: 'eve/compose/v2', 'x-eve': { egress }, services }) },
    { user_id: 'user_alice' },
  );
  return { run, lookups };
}

/**
 * x-eve.egress.hosts at sync: each declared exact host is resolved once and
 * refused when it points inside the cluster's or a private network (an FQDN
 * policy would open that address to the project's pods).
 */
describe('ManifestService.syncManifest: egress hosts that resolve to private addresses', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  });

  it('refuses a host that resolves to a private address, naming the host and the address, before anything is written', async () => {
    const { run } = await sync({ hosts: ['api.example.com', 'db.example.com'] });
    await expect(run).rejects.toThrow(/db\.example\.com.*10\.20\.0\.5/);
    expect(db.manifests.create).not.toHaveBeenCalled();
  });

  it("refuses a host in the instance's network.private_cidrs, and one a service declares", async () => {
    const { run } = await sync({ hosts: ['api.example.com'] }, {
      web: { image: 'web:1', 'x-eve': { egress: { hosts: ['svc.example.com'] } } },
    });
    await expect(run).rejects.toThrow(/svc\.example\.com.*34\.118\.224\.10/);
  });

  it('accepts public hosts, resolving each name once, and lets a name that does not resolve yet pass', async () => {
    const { run, lookups } = await sync({ hosts: ['api.example.com', { name: 'api.example.com', port: 8443 }, 'later.example.com', '*.cdn.example.com'] }, {
      web: { image: 'web:1', 'x-eve': { egress: { hosts: ['hooks.example.com', 'api.example.com'] } } },
    });
    await expect(run).resolves.toBeDefined();
    expect(lookups.sort()).toEqual(['api.example.com', 'hooks.example.com', 'later.example.com']);
  });
});
