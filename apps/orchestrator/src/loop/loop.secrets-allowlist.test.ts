import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  agents: { findByProjectAndId: vi.fn(), findByOrgAndSlug: vi.fn() },
}));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  agentQueries: vi.fn(() => mocks.agents),
}));

import { LoopService } from './loop.service';

type BuildInvocation = (
  job: Record<string, unknown>,
  attempt: Record<string, unknown>,
  project: Record<string, unknown>,
  projectId: string,
  workspacePath: string,
  enrichedDescription: string,
  routing: { harnessSpec: string; profileHash: string | null; profileSource: string | null },
) => Promise<{ secrets_allowlist?: string[] }>;

function buildInvocation(): BuildInvocation {
  const loop = Object.create(LoopService.prototype) as Record<string, unknown>;
  loop.db = (() => []) as never;
  loop.logger = { log: vi.fn(), warn: vi.fn(), error: vi.fn() };
  loop.resolveJobScope = vi.fn(async () => ({ orgFsMount: { mode: 'none' }, tokenScope: null }));
  return (loop as unknown as { buildInvocation: BuildInvocation }).buildInvocation.bind(loop);
}

function job(overrides: Record<string, unknown> = {}) {
  return {
    id: 'opps-a1b2c3d4', project_id: 'proj_opps', title: 'Triage', parent_id: null,
    hints: {}, harness_options: null, git_json: null, workspace_json: null, resource_refs: [],
    token_permissions: null, actor_user_id: null, user_secrets_excluded: false,
    secrets_allowlist: null, harness_profile: null, ...overrides,
  };
}

const attempt = { id: 'att_1', agent_id: 'triage' };
const project = { id: 'proj_opps', org_id: 'org_vdb', repo_url: 'https://github.com/org/repo', branch: 'main' };
const routing = { harnessSpec: 'claude', profileHash: null, profileSource: null };

beforeEach(() => vi.clearAllMocks());

describe('secrets allowlist on the harness invocation', () => {
  it('is absent when neither the agent nor the job declares one', async () => {
    mocks.agents.findByProjectAndId.mockResolvedValue({ access_json: { permissions: ['jobs:read'] } });

    const invocation = await buildInvocation()(job(), attempt, project, 'proj_opps', '/ws', '', routing);

    expect(invocation.secrets_allowlist).toBeUndefined();
  });

  it("carries the agent's access.secrets", async () => {
    mocks.agents.findByProjectAndId.mockResolvedValue({ access_json: { secrets: ['ANTHROPIC_API_KEY', 'OPPS_SIGNING_KEY'] } });

    const invocation = await buildInvocation()(job(), attempt, project, 'proj_opps', '/ws', '', routing);

    expect(mocks.agents.findByProjectAndId).toHaveBeenCalledWith('proj_opps', 'triage');
    expect(invocation.secrets_allowlist).toEqual(['ANTHROPIC_API_KEY', 'OPPS_SIGNING_KEY']);
  });

  it("narrows to the keys both the agent and the job's own allowlist name", async () => {
    mocks.agents.findByProjectAndId.mockResolvedValue({ access_json: { secrets: ['ANTHROPIC_API_KEY', 'OPPS_SIGNING_KEY'] } });

    const invocation = await buildInvocation()(
      job({ secrets_allowlist: ['OPPS_SIGNING_KEY', 'GITHUB_TOKEN'] }), attempt, project, 'proj_opps', '/ws', '', routing,
    );

    expect(invocation.secrets_allowlist).toEqual(['OPPS_SIGNING_KEY']);
  });

  it("applies the job's allowlist to a job with no agent", async () => {
    const invocation = await buildInvocation()(
      job({ secrets_allowlist: [] }), { id: 'att_2', agent_id: 'orchestrator' }, project, 'proj_opps', '/ws', '', routing,
    );

    expect(invocation.secrets_allowlist).toEqual([]);
  });

  it('carries the allowlist of an agent in another project that the job was routed to by slug', async () => {
    mocks.agents.findByProjectAndId.mockResolvedValue(null);
    mocks.agents.findByOrgAndSlug.mockResolvedValue({ id: 'triage', slug: 'triage', access_json: { secrets: ['OPPS_SIGNING_KEY'] } });

    const invocation = await buildInvocation()(
      job({ target: { agent_slug: 'triage' } }), attempt, project, 'proj_opps', '/ws', '', routing,
    );

    expect(mocks.agents.findByOrgAndSlug).toHaveBeenCalledWith('org_vdb', 'triage');
    expect(invocation.secrets_allowlist).toEqual(['OPPS_SIGNING_KEY']);
  });

  it('ignores a slug that now names a different agent than the one the job was assigned', async () => {
    mocks.agents.findByProjectAndId.mockResolvedValue(null);
    mocks.agents.findByOrgAndSlug.mockResolvedValue({ id: 'someone-else', slug: 'triage', access_json: { secrets: [] } });

    const invocation = await buildInvocation()(
      job({ target: { agent_slug: 'triage' } }), attempt, project, 'proj_opps', '/ws', '', routing,
    );

    expect(invocation.secrets_allowlist).toBeUndefined();
  });
});
