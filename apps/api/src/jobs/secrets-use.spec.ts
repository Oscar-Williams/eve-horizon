import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { JobsController } from './jobs.controller.js';
import { JobsService } from './jobs.service.js';
import { WorkflowsService } from '../workflows/workflows.service.js';
import { WorkflowsController } from '../workflows/workflows.controller.js';
import { ChatService } from '../chat/chat.service.js';
import { RbacService } from '../auth/rbac.service.js';
import { AccessService } from '../auth/access.service.js';
import { SecurityService } from '../security/security.service.js';
import type { AuthUser } from '../auth/auth.types.js';
import { accessStore as store } from '../auth/__tests__/access-store.js';

/**
 * Rule secrets.use (P2-7): starting work that receives a bound secret other
 * than its harness credential needs `secrets:use`, at job create, workflow
 * invoke and chat. Bound sets come from the declared allowlists and the env
 * overrides' secret references. A job that declares none is bound to nothing
 * beyond its harness credential, and a clone credential is never declared.
 */

const MANIFEST = `
name: shop
workflows:
  bound:
    steps:
      - name: sign
        agent:
          name: signer
          prompt: "Sign the release"
  harness-only:
    steps:
      - name: review
        agent:
          name: reviewer
          prompt: "Review"
  script-ref:
    steps:
      - name: publish
        script:
          run: "true"
        env_overrides:
          SIGNING_KEY: "\${secret.SHOP_SIGNING_KEY}"
`;

const m = vi.hoisted(() => {
  const jobs: Array<Record<string, unknown>> = [];
  let n = 0;
  return {
    jobs,
    manifests: {
      findByProjectAndGitSha: vi.fn(async () => null),
      findLatestByProject: vi.fn(async () => null as unknown),
    },
    jobQ: {
      resolveProjectSlug: vi.fn(async (id: string) => id),
      generateJobId: vi.fn(async (_p: string, parentId?: string) => ({ id: parentId ? `${parentId}.${++n}` : `shop-${++n}`, projectId: 'proj_shop' })),
      create: vi.fn(async (d: Record<string, unknown>) => {
        jobs.push(d);
        return { ...d, created_at: new Date(), updated_at: new Date() };
      }),
      addDependency: vi.fn(async () => 'rel'),
      updatePhase: vi.fn(async () => ({ success: true })),
    },
    appLinks: { listByConsumer: vi.fn(async () => []) },
    apiSources: { list: vi.fn(async () => []) },
    agents: {
      findByProjectAndId: vi.fn(async (_p: string, id: string) => AGENTS.find((a) => a.id === id) ?? null),
      findByOrgAndSlug: vi.fn(async (_o: string, slug: string) => AGENTS.find((a) => a.slug === slug) ?? null),
      listByProject: vi.fn(async () => AGENTS),
    },
  };
});

const AGENTS = [
  // Bound to a signing key beyond its harness credential.
  { id: 'signer', slug: 'signer', project_id: 'proj_shop', access_json: { secrets: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'] }, policies_json: null, harness_profile: null },
  // Bound to its harness credential only.
  { id: 'reviewer', slug: 'reviewer', project_id: 'proj_shop', access_json: { secrets: ['ANTHROPIC_API_KEY'] }, policies_json: null, harness_profile: null },
  // Declares nothing: unbound.
  { id: 'helper', slug: 'helper', project_id: 'proj_shop', access_json: {}, policies_json: null, harness_profile: null },
];

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  const { accessStore } = await import('../auth/__tests__/access-store.js');
  return {
    ...actual,
    ...accessStore.queries,
    projectManifestQueries: vi.fn(() => m.manifests),
    jobQueries: vi.fn(() => m.jobQ),
    appLinkSubscriptionQueries: vi.fn(() => m.appLinks),
    projectApiSourceQueries: vi.fn(() => m.apiSources),
    agentQueries: vi.fn(() => m.agents),
  };
});

const ORG = 'org_acme';
const PROJECT = 'proj_shop';
const member: AuthUser = { user_id: 'user_alice' };
const admin: AuthUser = { user_id: 'user_bob' };

function seed(profile: 'legacy' | 'audit' | 'strict') {
  store.reset();
  store.addOrg(ORG, 'acme');
  store.addProject(PROJECT, ORG, 'shop', profile, profile === 'strict' ? 2 : null);
  store.joinOrg(member.user_id, ORG, 'member');
  store.joinProject(member.user_id, PROJECT, 'member');
  store.joinOrg(admin.user_id, ORG, 'admin');
  m.jobs.length = 0;
  m.manifests.findLatestByProject.mockResolvedValue({ manifest_yaml: MANIFEST, manifest_hash: 'h', parsed_defaults: null });
}

function services() {
  const security = new SecurityService(store.db as never);
  const rbac = new RbacService(store.db as never, security);
  const access = new AccessService(rbac, store.db as never, security);
  const jobsService = new JobsService(store.db as never, {} as never, {} as never, {} as never, access, security, rbac);
  const workflowsService = new WorkflowsService(store.db as never, access, security, rbac);
  return {
    rbac,
    jobs: new JobsController(jobsService, rbac),
    workflows: new WorkflowsController(workflowsService, rbac),
  };
}

const job = (assignee: string, extra: Record<string, unknown> = {}) =>
  ({ description: 'Ship it', assignee, harness: 'claude', ...extra }) as never;

describe('secrets.use at job create', () => {
  it('under strict, refuses a member starting a job bound to a secret beyond its harness credential', async () => {
    seed('strict');
    const { jobs } = services();
    await expect(jobs.create(PROJECT, job('signer'), member, 'c')).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobs).toHaveLength(0);
    expect(store.findings('secrets.use')[0]).toMatchObject({ profile: 'strict', actor_id: member.user_id });
    expect(String(store.findings('secrets.use')[0]?.detail.secrets)).toBe('SHOP_SIGNING_KEY');
  });

  it('under strict, lets a member start a job bound only to its harness credential, or unbound', async () => {
    seed('strict');
    const { jobs } = services();
    await expect(jobs.create(PROJECT, job('reviewer'), member, 'c')).resolves.toBeDefined();
    await expect(jobs.create(PROJECT, job('helper'), member, 'c')).resolves.toBeDefined();
    expect(m.jobs).toHaveLength(2);
    expect(store.findings('secrets.use')).toEqual([]);
  });

  it('under strict, lets an admin start the bound job', async () => {
    seed('strict');
    const { jobs } = services();
    await expect(jobs.create(PROJECT, job('signer'), admin, 'c')).resolves.toBeDefined();
  });

  it('counts a secret the job token narrows to, and the allowlist the starting job carries', async () => {
    seed('strict');
    const { jobs } = services();
    const token = {
      user_id: member.user_id, is_job_token: true, job_id: 'shop-0', project_id: PROJECT, org_id: ORG,
      permissions: ['jobs:read', 'jobs:write', 'secrets:read'], secrets_allowlist: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'],
    } as AuthUser;
    await expect(jobs.create(PROJECT, job('helper'), token, 'c')).rejects.toBeInstanceOf(ForbiddenException);
    const declared = { ...token, permissions: [...(token.permissions ?? []), 'secrets:use'] } as AuthUser;
    await expect(jobs.create(PROJECT, job('helper'), declared, 'c')).resolves.toBeDefined();
  });

  it('under audit, lets the member start it and records the use of secrets:read', async () => {
    seed('audit');
    const { jobs } = services();
    await expect(jobs.create(PROJECT, job('signer'), member, 'c')).resolves.toBeDefined();
    expect(store.findings('access.operator_rights')[0]?.detail).toMatchObject({ permission: 'secrets:use', implied_by: 'secrets:read' });
  });

  it('under legacy, changes nothing', async () => {
    seed('legacy');
    const { jobs } = services();
    await expect(jobs.create(PROJECT, job('signer'), member, 'c')).resolves.toBeDefined();
    expect(store.findings()).toEqual([]);
  });
});

describe('secrets.use at workflow invoke', () => {
  it('under strict, refuses a member before any job is created', async () => {
    seed('strict');
    const { workflows } = services();
    await expect(workflows.invoke(PROJECT, 'bound', {} as never, member)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobs).toHaveLength(0);
  });

  it('counts a script step that references a secret in its env overrides', async () => {
    seed('strict');
    const { workflows } = services();
    await expect(workflows.invoke(PROJECT, 'script-ref', {} as never, member)).rejects.toBeInstanceOf(ForbiddenException);
    expect(m.jobs).toHaveLength(0);
  });

  it('under strict, lets a member run a workflow bound only to the harness credential, and an admin run the bound one', async () => {
    seed('strict');
    const { workflows } = services();
    await expect(workflows.invoke(PROJECT, 'harness-only', {} as never, member)).resolves.toBeDefined();
    await expect(workflows.invoke(PROJECT, 'bound', {} as never, admin)).resolves.toBeDefined();
  });

  it('under audit, runs it for the member and records the use', async () => {
    seed('audit');
    const { workflows } = services();
    await expect(workflows.invoke(PROJECT, 'bound', {} as never, member)).resolves.toBeDefined();
    expect(store.findings('access.operator_rights')[0]?.detail).toMatchObject({ permission: 'secrets:use' });
  });
});

describe('secrets.use at chat', () => {
  type Priv = {
    createChatJob(ctx: { user?: AuthUser } | undefined, projectId: string, data: Record<string, unknown>, request?: Record<string, unknown>): Promise<{ id: string }>;
  };

  it('holds the sender the gateway mapped, or no one, to the rule', async () => {
    seed('strict');
    const security = new SecurityService(store.db as never);
    const rbac = new RbacService(store.db as never, security);
    const access = new AccessService(rbac, store.db as never, security);
    const jobsService = new JobsService(store.db as never, {} as never, {} as never, {} as never, access, security, rbac);
    const chat = new ChatService((() => ({})) as never, jobsService, rbac) as unknown as Priv;

    await expect(chat.createChatJob(undefined, PROJECT, job('signer'), { metadata: { eve_user_id: member.user_id } }))
      .rejects.toBeInstanceOf(ForbiddenException);
    await expect(chat.createChatJob(undefined, PROJECT, job('signer'), { metadata: {} }))
      .rejects.toBeInstanceOf(ForbiddenException);
    await expect(chat.createChatJob(undefined, PROJECT, job('signer'), { metadata: { eve_user_id: admin.user_id } }))
      .resolves.toBeDefined();
    await expect(chat.createChatJob({ user: member }, PROJECT, job('reviewer'))).resolves.toBeDefined();
    expect(store.findings('secrets.use').map((f) => f.actor_type)).toEqual(expect.arrayContaining(['user', 'none']));
  });
});
