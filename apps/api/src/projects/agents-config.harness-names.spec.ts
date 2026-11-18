import { beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import type { SecurityProfile } from '@eve/shared';
import { AgentsConfigService } from './agents-config.service';
import type { SecurityService } from '../security/security.service';

const mocks = vi.hoisted(() => ({
  projects: { findById: vi.fn() },
  orgs: { findById: vi.fn() },
  manifests: { findLatestByProject: vi.fn() },
  agents: {
    listByOrgAndSlugs: vi.fn(async () => []),
    listByOrgAndAliases: vi.fn(async () => []),
    deleteByProject: vi.fn(),
    insert: vi.fn(),
  },
  teams: { deleteByProject: vi.fn(), insert: vi.fn() },
  teamMembers: { deleteByProject: vi.fn(), insert: vi.fn() },
  agentConfigs: { create: vi.fn() },
}));

vi.mock('@eve/db', () => ({
  projectQueries: vi.fn(() => mocks.projects),
  orgQueries: vi.fn(() => mocks.orgs),
  projectManifestQueries: vi.fn(() => mocks.manifests),
  agentConfigQueries: vi.fn(() => mocks.agentConfigs),
  agentQueries: vi.fn(() => mocks.agents),
  teamQueries: vi.fn(() => mocks.teams),
  teamMemberQueries: vi.fn(() => mocks.teamMembers),
}));

const MANIFEST = [
  'x-eve:',
  '  agents:',
  '    profiles:',
  '      triage:',
  '        - harness: claude',
  'workflows:',
  '  triage:',
  '    steps:',
  '      - name: judge',
  '        agent:',
  '          name: triage',
  '          prompt: Run',
].join('\n');

function agentsYaml(agents: Record<string, Record<string, unknown>>): string {
  const lines = ['version: 1', 'agents:'];
  for (const [id, fields] of Object.entries(agents)) {
    lines.push(`  ${id}:`, `    skill: ${id}`);
    for (const [key, value] of Object.entries(fields)) lines.push(`    ${key}: ${value}`);
  }
  return lines.join('\n') + '\n';
}

function request(agents: Record<string, Record<string, unknown>>, xEveYaml?: string) {
  return {
    agents_yaml: agentsYaml(agents),
    teams_yaml: 'version: 1\nteams: {}\n',
    chat_yaml: 'version: 1\nroutes: []\n',
    ...(xEveYaml ? { x_eve_yaml: xEveYaml } : {}),
  };
}

function fakeSecurity(profile: SecurityProfile) {
  return {
    gate: vi.fn(async (rule: string, _ctx: unknown, message?: string) => {
      if (profile === 'legacy') return 'allowed';
      if (profile === 'strict') throw new ForbiddenException(`${message ?? 'Refused'} (rule ${rule})`);
      return 'recorded';
    }),
  };
}

function service(profile: SecurityProfile) {
  const security = fakeSecurity(profile);
  const db = { begin: async (fn: (tx: unknown) => unknown) => fn({}) };
  return { svc: new AgentsConfigService(db as never, security as unknown as SecurityService), security };
}

describe('AgentsConfigService: harness profiles and workflow agents at sync', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocks.projects.findById.mockResolvedValue({ id: 'proj_trg', org_id: 'org_1' });
    mocks.orgs.findById.mockResolvedValue({ id: 'org_1', default_agent_slug: null });
    mocks.manifests.findLatestByProject.mockResolvedValue({ manifest_yaml: MANIFEST });
    mocks.agentConfigs.create.mockImplementation(async (row: Record<string, unknown>) => ({
      ...row,
      created_at: new Date('2026-11-18T00:00:00.000Z'),
      updated_at: new Date('2026-11-18T00:00:00.000Z'),
    }));
  });

  it('refuses under strict an agent whose harness profile is not declared', async () => {
    const { svc, security } = service('strict');

    await expect(svc.syncAgentsConfig('proj_trg', request({ triage: { harness_profile: 'missing' } })))
      .rejects.toBeInstanceOf(ForbiddenException);
    expect(security.gate).toHaveBeenCalledWith('harness.missing_profile', expect.objectContaining({
      projectId: 'proj_trg',
      governing: 'project',
    }), expect.stringMatching(/missing/));
    expect(mocks.agentConfigs.create).not.toHaveBeenCalled();
  });

  it('refuses under strict when a workflow step names an agent this sync does not define', async () => {
    const { svc, security } = service('strict');

    await expect(svc.syncAgentsConfig('proj_trg', request({ helper: { harness_profile: 'triage' } })))
      .rejects.toBeInstanceOf(ForbiddenException);
    expect(security.gate).toHaveBeenCalledWith('harness.missing_agent', expect.anything(), expect.stringMatching(/triage/));
  });

  it('reads profiles from the synced agents config before the manifest, as dispatch does', async () => {
    const { svc, security } = service('strict');
    const xEve = 'agents:\n  profiles:\n    pack-profile:\n      - harness: claude\n';

    await expect(svc.syncAgentsConfig('proj_trg', request({ triage: { harness_profile: 'triage' } }, xEve)))
      .rejects.toBeInstanceOf(ForbiddenException);
    await expect(svc.syncAgentsConfig('proj_trg', request({ triage: { harness_profile: 'pack-profile' } }, xEve)))
      .resolves.toBeDefined();
    expect(security.gate).toHaveBeenCalledTimes(1);
  });

  it('syncs under audit and records each gap', async () => {
    const { svc, security } = service('audit');

    await expect(svc.syncAgentsConfig('proj_trg', request({ helper: { harness_profile: 'missing' } })))
      .resolves.toBeDefined();
    expect(security.gate.mock.calls.map((call) => call[0]).sort()).toEqual(['harness.missing_agent', 'harness.missing_profile']);
  });

  it('decides nothing when every name resolves', async () => {
    const { svc, security } = service('strict');

    await expect(svc.syncAgentsConfig('proj_trg', request({ triage: { harness_profile: 'triage' } })))
      .resolves.toBeDefined();
    expect(security.gate).not.toHaveBeenCalled();
  });
});
