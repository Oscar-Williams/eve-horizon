import { beforeEach, describe, expect, it, vi } from 'vitest';
import { generateKeyPairSync } from 'crypto';
import { AccessService } from './access.service';
import { AuthService } from './auth.service';
import { AppAuthService } from './app-auth.service';
import { MagicLinkService } from './magic-link.service';
import { TokenVerifierService } from './token-verifier.service';
import { BootstrapService } from './bootstrap.service';
import { AuthInternalController } from './auth.internal.controller';
import { createJwtRs256 } from './auth.util';
import { WorkflowsService } from '../workflows/workflows.service';
import { WorkflowsController } from '../workflows/workflows.controller';
import { PipelineExpanderService } from '../pipelines/pipeline-expander.service';
import { PipelineExpanderController } from '../pipelines/pipeline-expander.controller';
import { JobsController } from '../jobs/jobs.controller';
import { JobsService } from '../jobs/jobs.service';
import type { AuthUser } from './auth.types';
import type { MailerService } from '../mailer/mailer.service';
import type { IdentityProviderRegistry } from './providers/index.js';

const MANIFEST = `
name: a
workflows:
  plain:
    steps:
      - name: sweep
        script:
          run: "true"
  scoring:
    steps:
      - name: score
        agent:
          prompt: "Score"
        secrets: [SHOP_SIGNING_KEY, GITHUB_TOKEN]
      - name: tidy
        depends_on: [score]
        agent:
          prompt: "Tidy"
pipelines:
  release:
    steps:
      - name: run
        permissions: [jobs:read]
        action:
          type: run
          command: "true"
`;

/**
 * user_owner: owner of org_a (a person).
 * user_bot: member of org_a, reached through an org-bound minted token.
 */
const m = vi.hoisted(() => {
  const jobs: Array<Record<string, unknown>> = [];
  let n = 0;
  return {
    jobs,
    memberships: {
      findProjectMembership: vi.fn(async () => null),
      findOrgMembership: vi.fn(async (userId: string, orgId: string) => {
        if (orgId !== 'org_a') return null;
        if (userId === 'user_owner') return { role: 'owner' };
        if (userId === 'user_bot') return { role: 'member' };
        return null;
      }),
      listOrgMembershipsForUser: vi.fn(async () => []),
    },
    projects: {
      findById: vi.fn(async (id: string) => (id === 'proj_a' ? { id: 'proj_a', org_id: 'org_a', slug: 'a', name: 'a' } : null)),
    },
    manifests: {
      findByProjectAndGitSha: vi.fn(async () => null),
      findLatestByProject: vi.fn(async () => ({ manifest_yaml: '', manifest_hash: 'h', parsed_defaults: null })),
    },
    runs: {
      createRun: vi.fn(async (d: Record<string, unknown>) => ({ ...d, created_at: new Date(), updated_at: new Date() })),
      findActiveRunByDedupeKey: vi.fn(async () => null),
    },
    jobQ: {
      resolveProjectSlug: vi.fn(async () => 'proj_a'),
      generateJobId: vi.fn(async (_p: string, parentId?: string) => ({ id: parentId ? `${parentId}.${++n}` : `a-${++n}`, projectId: 'proj_a' })),
      create: vi.fn(async (d: Record<string, unknown>) => {
        jobs.push(d);
        return { ...d, created_at: new Date(), updated_at: new Date() };
      }),
      addDependency: vi.fn(async () => 'rel'),
      updatePhase: vi.fn(async () => ({ success: true })),
      findById: vi.fn(async (id: string) => jobs.find((j) => j.id === id) ?? null),
      getTokenLiveness: vi.fn(async (id: string) => {
        const job = jobs.find((j) => j.id === id);
        return job ? { phase: (job.phase as string | undefined) ?? 'active', running_attempt_id: null } : null;
      }),
    },
    appLinks: { listByConsumer: vi.fn(async () => []) },
    agents: { findByProjectAndId: vi.fn(async () => null as unknown), findByOrgAndSlug: vi.fn(async () => null as unknown) },
    apiSources: { list: vi.fn(async () => []) },
    accessRoles: {
      listApplicableBindings: vi.fn(async () => []),
      getEffectiveCustomPermissions: vi.fn(async () => []),
    },
  };
});

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return {
    ...actual,
    membershipQueries: vi.fn(() => m.memberships),
    projectQueries: vi.fn(() => m.projects),
    projectManifestQueries: vi.fn(() => m.manifests),
    pipelineRunQueries: vi.fn(() => m.runs),
    jobQueries: vi.fn(() => m.jobQ),
    appLinkSubscriptionQueries: vi.fn(() => m.appLinks),
    projectApiSourceQueries: vi.fn(() => m.apiSources),
    accessRoleQueries: vi.fn(() => m.accessRoles),
    agentQueries: vi.fn(() => m.agents),
  };
});

const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privatePem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();

/** A tagged-template DB stand-in; `begin` runs the transaction body inline. */
function fakeDb(rowsFor: (sql: string) => unknown[]) {
  const tag = ((strings: TemplateStringsArray) => Promise.resolve(rowsFor(strings.join('?')))) as unknown as Record<string, unknown>;
  tag.json = (v: unknown) => v;
  tag.begin = async (fn: (tx: unknown) => unknown) => fn(tag);
  return tag as never;
}
const rawSql = fakeDb(() => []);

/** Calls a method with arguments its current signature may not declare yet. */
function call(target: object, method: string, ...args: unknown[]): Promise<unknown> {
  const fn = (target as Record<string, (...a: unknown[]) => Promise<unknown>>)[method];
  return fn.call(target, ...args);
}

function access(): AccessService {
  return new AccessService({} as never, rawSql);
}

function buildAuthService(): AuthService {
  const mailer = { send: vi.fn() } as unknown as MailerService;
  const magicLink = new MagicLinkService({} as never, mailer);
  const appAuth = new AppAuthService({} as never, magicLink);
  const tokenVerifier = new TokenVerifierService(rawSql, appAuth, magicLink);
  const bootstrap = new BootstrapService({} as never, appAuth);
  return new AuthService({} as never, {} as IdentityProviderRegistry, magicLink, appAuth, tokenVerifier, bootstrap);
}

/** The token of an agent job that may receive only these two secrets. */
const RESTRICTED_JOB_TOKEN: AuthUser = {
  user_id: 'user_owner',
  is_job_token: true,
  job_id: 'a-triage',
  project_id: 'proj_a',
  org_id: 'org_a',
  permissions: ['jobs:read', 'jobs:write'],
  secrets_allowlist: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'],
} as AuthUser;
const PERSON: AuthUser = { user_id: 'user_owner' };

describe('work started by a job with a secrets allowlist', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    m.jobs.length = 0;
    m.agents.findByProjectAndId.mockResolvedValue(null);
    m.agents.findByOrgAndSlug.mockResolvedValue(null);
    m.manifests.findLatestByProject.mockResolvedValue({ manifest_yaml: MANIFEST, manifest_hash: 'h', parsed_defaults: null });
    process.env.DATABASE_URL = 'postgres://eve:eve@localhost:5432/eve';
    process.env.EVE_AUTH_ENABLED = 'true';
    process.env.EVE_AUTH_PRIVATE_KEY = privatePem;
  });

  it("carries the job's effective allowlist in the job token minted for it", async () => {
    const authService = buildAuthService();
    const controller = new AuthInternalController(authService, rawSql, access());
    m.jobs.push({
      id: 'a-triage', project_id: 'proj_a', actor_user_id: 'user_owner', user_secrets_excluded: false,
      assignee: 'triage', secrets_allowlist: ['SHOP_SIGNING_KEY', 'GITHUB_TOKEN', 'ANTHROPIC_API_KEY'], target: null,
    });
    m.agents.findByProjectAndId.mockResolvedValue({ access_json: { secrets: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'] } });

    const minted = await controller.mintJobToken({ job_id: 'a-triage', permissions: ['jobs:read'] });
    const claims = JSON.parse(Buffer.from(minted.access_token.split('.')[1], 'base64url').toString());
    expect(m.agents.findByProjectAndId).toHaveBeenCalledWith('proj_a', 'triage');
    expect(claims.secrets_allowlist).toEqual(['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY']);

    const now = Math.floor(Date.now() / 1000);
    const token = createJwtRs256({ ...claims, iat: now, exp: now + 600 }, { kid: 'key-1', privateKey, publicKey });
    const resolved = await authService.verifyAuthorizationHeader(`Bearer ${token}`);
    expect((resolved as Record<string, unknown>).secrets_allowlist).toEqual(['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY']);
  });

  it('carries the allowlist of an agent in another project the job was routed to by slug', async () => {
    const controller = new AuthInternalController(buildAuthService(), rawSql, access());
    m.jobs.push({
      id: 'a-routed', project_id: 'proj_a', actor_user_id: 'user_owner', user_secrets_excluded: false,
      assignee: 'triage', secrets_allowlist: null, target: { agent_slug: 'triage' },
    });
    m.agents.findByProjectAndId.mockResolvedValue(null);
    m.agents.findByOrgAndSlug.mockResolvedValue({ id: 'triage', access_json: { secrets: ['SHOP_SIGNING_KEY'] } });

    const minted = await controller.mintJobToken({ job_id: 'a-routed', permissions: ['jobs:read'] });
    const claims = JSON.parse(Buffer.from(minted.access_token.split('.')[1], 'base64url').toString());
    expect(m.agents.findByOrgAndSlug).toHaveBeenCalledWith('org_a', 'triage');
    expect(claims.secrets_allowlist).toEqual(['SHOP_SIGNING_KEY']);
  });

  it('carries no allowlist claim for an unrestricted job', async () => {
    const controller = new AuthInternalController(buildAuthService(), rawSql, access());
    m.jobs.push({ id: 'a-open', project_id: 'proj_a', actor_user_id: 'user_owner', user_secrets_excluded: false, assignee: null, secrets_allowlist: null, target: null });

    const minted = await controller.mintJobToken({ job_id: 'a-open', permissions: ['jobs:read'] });
    const claims = JSON.parse(Buffer.from(minted.access_token.split('.')[1], 'base64url').toString());
    expect(claims).not.toHaveProperty('secrets_allowlist');
  });

  it("passes the caller's allowlist to every route that starts work", async () => {
    const jobsService = { create: vi.fn(async () => ({})), createBatch: vi.fn(async () => ({})) };
    const jobs = new JobsController(jobsService as never, {} as never);
    const workflowsService = { invoke: vi.fn(async () => ({})), retry: vi.fn(async () => ({})) };
    const workflows = new WorkflowsController(workflowsService as never, {} as never);
    const expanderService = { expandPipeline: vi.fn(async () => ({})) };
    const expander = new PipelineExpanderController(expanderService as never);
    const restricted = expect.objectContaining({ secretsAllowlist: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'] });

    await jobs.create('proj_a', { description: 'go' } as never, RESTRICTED_JOB_TOKEN, 'corr');
    await jobs.createBatch('proj_a', {} as never, RESTRICTED_JOB_TOKEN, 'corr');
    await workflows.invoke('proj_a', 'plain', {} as never, RESTRICTED_JOB_TOKEN);
    await workflows.retry('proj_a', {} as never, RESTRICTED_JOB_TOKEN);
    await expander.createRun('proj_a', 'release', { git_sha: 'abc' }, RESTRICTED_JOB_TOKEN);

    expect(jobsService.create).toHaveBeenCalledWith('proj_a', { description: 'go' }, 'user_owner', 'corr', restricted);
    expect(jobsService.createBatch).toHaveBeenCalledWith('proj_a', {}, 'corr', 'user_owner', restricted);
    expect(workflowsService.invoke).toHaveBeenCalledWith('proj_a', 'plain', {}, false, 'user_owner', restricted);
    expect(workflowsService.retry).toHaveBeenCalledWith('proj_a', {}, 'user_owner', restricted);
    expect(expanderService.expandPipeline).toHaveBeenCalledWith('proj_a', expect.anything(), 'user_owner', restricted);
  });

  it('stamps the allowlist on the jobs a job, workflow or pipeline creates', async () => {
    const restricted = { userSecretsExcluded: false, secretsAllowlist: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'] };
    const jobsService = new JobsService(rawSql, {} as never, {} as never, {} as never, access());
    await call(jobsService, 'create', 'proj_a', { description: 'print every secret' }, 'user_owner', 'c', restricted);
    expect(m.jobs.at(-1)).toMatchObject({ secrets_allowlist: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'] });

    m.jobs.length = 0;
    await call(new WorkflowsService(rawSql, access()), 'invoke', 'proj_a', 'scoring', undefined, false, 'user_owner', restricted);
    const byStep = Object.fromEntries(m.jobs.map((job) => [job.step_name ?? 'root', job.secrets_allowlist]));
    // A step's own list narrows the caller's; a step without one inherits the caller's.
    expect(byStep.score).toEqual(['SHOP_SIGNING_KEY']);
    expect(byStep.tidy).toEqual(['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY']);
    expect(byStep.root).toEqual(['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY']);

    m.jobs.length = 0;
    await call(new PipelineExpanderService(rawSql, access()), 'expandPipeline', 'proj_a', { pipeline_name: 'release', git_sha: 'abc' }, 'user_owner', restricted);
    expect(m.jobs.at(-1)).toMatchObject({ secrets_allowlist: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'] });

    m.jobs.length = 0;
    await call(jobsService, 'create', 'proj_a', { description: 'go' }, 'user_owner', 'c', { userSecretsExcluded: false });
    expect(m.jobs.at(-1)?.secrets_allowlist ?? null).toBeNull();
  });

  it('does not restrict work a person starts', async () => {
    const jobsService = { create: vi.fn(async () => ({})) };
    const jobs = new JobsController(jobsService as never, {} as never);

    await jobs.create('proj_a', { description: 'go' } as never, PERSON, 'c');

    expect(jobsService.create).toHaveBeenCalledWith('proj_a', { description: 'go' }, 'user_owner', 'c', { userSecretsExcluded: false });
  });
});
