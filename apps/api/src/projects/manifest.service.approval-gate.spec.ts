import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException } from '@nestjs/common';
import { ManifestService } from './manifest.service';
import { SecurityService } from '../security/security.service';
import type { SecretsService } from '../secrets/secrets.service';

/**
 * EVE-056: `environments.<env>.approval` promises a deploy gate Eve does not
 * enforce. Rule manifest.approval_unenforced (project, rule set 4): `strict`
 * refuses the sync (400, naming the option), `audit` syncs with a warning and
 * records what strict would refuse, `legacy` gives the warning only. A
 * `strict` stamped at rule set 3 runs the rule as `audit` until it is
 * stamped again.
 *
 * The security service is the real one; the project's profile, its stamp and
 * the findings live in the stand-ins below.
 */
const db = vi.hoisted(() => {
  const state = {
    projectProfile: null as string | null,
    projectRuleset: null as number | null,
    findings: [] as Array<Record<string, unknown>>,
  };

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

  const projects = stub({
    findById: vi.fn(async (id: string) => ({ id, org_id: 'org_acme', slug: 'shop', auth_config: null })),
  });
  const manifests = stub({
    create: vi.fn(async (row: Record<string, unknown>) => ({ ...row, created_at: new Date(), updated_at: new Date() })),
  });

  return { state, projects, manifests, stub };
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
    environmentQueries: vi.fn(() => db.stub({})),
    ingressAliasQueries: vi.fn(() => db.stub({})),
    customDomainQueries: vi.fn(() => db.stub({})),
    appLinkGrantQueries: vi.fn(() => db.stub({})),
    appLinkSubscriptionQueries: vi.fn(() => db.stub({})),
    systemSettingsQueries: vi.fn(() => ({ get: vi.fn(async () => null) })),
    securityQueries: vi.fn(() => ({
      getProfiles: vi.fn(async () => ({
        org_id: 'org_acme',
        org_profile: null,
        org_ruleset: null,
        project_profile: db.state.projectProfile,
        project_ruleset: db.state.projectRuleset,
      })),
      recordFinding: vi.fn(async (finding: Record<string, unknown>) => {
        db.state.findings.push(finding);
      }),
    })),
  };
});

const GATED = JSON.stringify({
  schema: 'eve/compose/v2',
  services: { web: { image: 'shop:latest' } },
  environments: {
    staging: {},
    prod: { approval: 'required' },
  },
});

const UNGATED = JSON.stringify({
  schema: 'eve/compose/v2',
  services: { web: { image: 'shop:latest' } },
  environments: { staging: {}, prod: {} },
});

function sync(yaml: string) {
  const service = new ManifestService(
    { begin: async (fn: (tx: unknown) => Promise<unknown>) => fn({}) } as never,
    {} as SecretsService,
    new SecurityService({} as never),
  );
  return (service.syncManifest as (...args: unknown[]) => Promise<{ warnings?: string[] }>)(
    'proj_shop',
    { yaml },
    { user_id: 'user_alice' },
  );
}

function findings() {
  return db.state.findings.filter((finding) => finding.rule === 'manifest.approval_unenforced');
}

const NOT_ENFORCED = /Environment approval gates are not enforced by Eve\. Remove `approval` from environments\.prod\./;

beforeEach(() => {
  vi.clearAllMocks();
  process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
  db.state.projectProfile = null;
  db.state.projectRuleset = null;
  db.state.findings = [];
});

describe('ManifestService.syncManifest: environment approval gates (rule manifest.approval_unenforced)', () => {
  it('refuses under strict with 400 naming the option, and writes nothing', async () => {
    db.state.projectProfile = 'strict';
    db.state.projectRuleset = 4;

    const refused = sync(GATED);

    await expect(refused).rejects.toBeInstanceOf(BadRequestException);
    await expect(refused).rejects.toThrow(NOT_ENFORCED);
    expect(db.manifests.create).not.toHaveBeenCalled();
    expect(findings()).toEqual([
      expect.objectContaining({ profile: 'strict', project_id: 'proj_shop', detail: { environments: 'prod' } }),
    ]);
  });

  it('syncs under audit with the warning, and records what strict would refuse', async () => {
    db.state.projectProfile = 'audit';

    const response = await sync(GATED);

    expect(response.warnings?.join('\n')).toMatch(NOT_ENFORCED);
    expect(db.manifests.create).toHaveBeenCalled();
    expect(findings()).toEqual([
      expect.objectContaining({ profile: 'audit', actor_type: 'user', actor_id: 'user_alice', detail: { environments: 'prod' } }),
    ]);
  });

  it('syncs under legacy with the warning only', async () => {
    db.state.projectProfile = 'legacy';

    const response = await sync(GATED);

    expect(response.warnings?.join('\n')).toMatch(NOT_ENFORCED);
    expect(findings()).toEqual([]);
  });

  it('records under a strict stamped at rule set 3, and refuses only once stamped at 4', async () => {
    db.state.projectProfile = 'strict';
    db.state.projectRuleset = 3;

    const response = await sync(GATED);

    expect(response.warnings?.join('\n')).toMatch(NOT_ENFORCED);
    expect(findings()).toEqual([expect.objectContaining({ profile: 'audit' })]);

    db.state.projectRuleset = 4;
    await expect(sync(GATED)).rejects.toBeInstanceOf(BadRequestException);
  });

  it('says nothing about environments that set no approval', async () => {
    db.state.projectProfile = 'strict';
    db.state.projectRuleset = 4;

    const response = await sync(UNGATED);

    expect(response.warnings ?? []).toEqual([]);
    expect(findings()).toEqual([]);
  });
});
