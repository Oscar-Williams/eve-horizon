import { describe, expect, it, vi } from 'vitest';
import {
  findHarnessProfile,
  findUndeclaredHarnessNames,
  lookupProfile,
  readDeclaredProfiles,
  type ResolverDeps,
} from '../profile-resolver.js';

function deps(xEveYaml: string | null, manifestYaml: string | null): ResolverDeps {
  return {
    agentConfigs: { findLatestByProject: vi.fn().mockResolvedValue(xEveYaml === null ? null : { x_eve_yaml: xEveYaml }) },
    manifests: { findLatestByProject: vi.fn().mockResolvedValue(manifestYaml === null ? null : { manifest_yaml: manifestYaml }) },
    logger: { warn: vi.fn() },
  };
}

const MANIFEST = 'x-eve:\n  agents:\n    profiles:\n      triage:\n        - harness: claude\n          model: claude-sonnet-5-5\n';

describe('findHarnessProfile', () => {
  it('finds a declared profile', async () => {
    await expect(findHarnessProfile(deps(null, MANIFEST), 'proj', 'triage')).resolves.toEqual({
      status: 'found',
      harness: 'claude',
      harness_options: { model: 'claude-sonnet-5-5' },
    });
  });

  it('reports a profile nobody declares as missing', async () => {
    await expect(findHarnessProfile(deps(null, MANIFEST), 'proj', 'other')).resolves.toEqual({ status: 'missing' });
    await expect(findHarnessProfile(deps(null, null), 'proj', 'triage')).resolves.toEqual({ status: 'missing' });
  });

  it('reports a read failure as an error, where lookupProfile falls back', async () => {
    const failing: ResolverDeps = {
      agentConfigs: { findLatestByProject: vi.fn().mockRejectedValue(new Error('connection reset')) },
      manifests: { findLatestByProject: vi.fn() },
    };
    await expect(findHarnessProfile(failing, 'proj', 'triage')).resolves.toMatchObject({ status: 'error' });
    await expect(lookupProfile(failing, 'proj', 'triage')).resolves.toEqual({});
  });

  it('reports an unparseable agents config as an error, where lookupProfile still reads the manifest', async () => {
    const broken = deps('agents: [unclosed', MANIFEST);
    await expect(findHarnessProfile(broken, 'proj', 'triage')).resolves.toMatchObject({ status: 'error' });
    await expect(lookupProfile(broken, 'proj', 'triage')).resolves.toMatchObject({ harness: 'claude' });
  });
});

describe('readDeclaredProfiles', () => {
  it('prefers the agents config profiles over the manifest', () => {
    const declared = readDeclaredProfiles({
      xEveYaml: 'agents:\n  profiles:\n    pack:\n      - harness: zai\n',
      manifestYaml: MANIFEST,
    });
    expect(Object.keys(declared.profiles ?? {})).toEqual(['pack']);
  });

  it('falls back to the manifest when the agents config declares none', () => {
    expect(Object.keys(readDeclaredProfiles({ xEveYaml: 'packs: []\n', manifestYaml: MANIFEST }).profiles ?? {}))
      .toEqual(['triage']);
  });
});

describe('findUndeclaredHarnessNames', () => {
  const workflows = {
    triage: {
      steps: [
        { name: 'judge', agent: { name: 'triage' }, harness_profile: 'triage' },
        { name: 'fanout', agent: { prompt: 'x' }, harness_profile: '${inputs.profile}' },
        { name: 'ghost', agent: { name: 'nobody' }, harness_profile: 'missing' },
      ],
    },
  };

  it('lists undeclared profiles and agents, skipping templated names', () => {
    const gaps = findUndeclaredHarnessNames({
      workflows,
      agents: { triage: { harness_profile: 'triage' }, helper: { harness_profile: 'gone' } },
      profiles: new Set(['triage']),
      agentIds: new Set(['triage', 'helper']),
    });
    expect(gaps).toEqual([
      { kind: 'profile', name: 'gone', where: 'agent "helper"' },
      { kind: 'profile', name: 'missing', where: 'workflow "triage" step "ghost"', workflow: 'triage', step: 'ghost' },
      { kind: 'agent', name: 'nobody', where: 'workflow "triage" step "ghost"', workflow: 'triage', step: 'ghost' },
    ]);
  });

  it('checks only what it is given', () => {
    expect(findUndeclaredHarnessNames({ workflows, agentIds: new Set(['triage']) }).map((gap) => gap.kind)).toEqual(['agent']);
    expect(findUndeclaredHarnessNames({ workflows })).toEqual([]);
  });
});
