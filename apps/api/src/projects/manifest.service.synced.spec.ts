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
      findByProjectAndHash: vi.fn(async () => null as Record<string, unknown> | null),
      markSynced: vi.fn(async (id: string) => ({ id })),
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

async function sync(manifest: Record<string, unknown>): Promise<void> {
  const service = new ManifestService(
    { begin: async (fn: (tx: unknown) => Promise<unknown>) => fn({}) } as never,
    {} as SecretsService,
  );
  await (service.syncManifest as (...args: unknown[]) => Promise<unknown>)(
    'proj_shop',
    { yaml: JSON.stringify({ schema: 'eve/compose/v2', ...manifest }) },
    { user_id: 'user_alice' },
  );
}

/**
 * Runner egress allow lists are read from the manifest of the project's
 * last explicit sync or deploy (synced_at), never from a row the pipeline's
 * drift check stored from a built ref: an explicit sync marks its row.
 */
describe('ManifestService.syncManifest: the explicit sync mark', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  });

  it('marks a new manifest row synced', async () => {
    await sync({ services: { web: { image: 'web:1' } } });
    const created = db.manifests.create.mock.calls[0][0] as { id: string };
    expect(db.manifests.markSynced).toHaveBeenCalledWith(created.id);
  });

  it('marks an existing row with the same content synced again', async () => {
    db.manifests.findByProjectAndHash.mockResolvedValueOnce({
      id: 'man_old', project_id: 'proj_shop', manifest_yaml: '', manifest_hash: 'h', git_sha: null, branch: null,
      parsed_defaults: null, parsed_agents: null, created_at: new Date(), updated_at: new Date(),
    });
    await sync({ services: { web: { image: 'web:1' } } });
    expect(db.manifests.create).not.toHaveBeenCalled();
    expect(db.manifests.markSynced).toHaveBeenCalledWith('man_old');
  });
});
