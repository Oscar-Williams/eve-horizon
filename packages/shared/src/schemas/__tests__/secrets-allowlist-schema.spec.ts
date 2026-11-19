import { describe, expect, it } from 'vitest';
import { AgentsYamlSchema } from '../agent-config.js';
import { WorkflowStepSchema } from '../workflow.js';

describe('secrets allowlist in agent and workflow config', () => {
  it('accepts access.secrets on an agent', () => {
    const parsed = AgentsYamlSchema.safeParse({
      version: 1,
      agents: {
        triage: { skill: 'ticket-review', access: { secrets: ['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY'] } },
      },
    });
    expect(parsed.success).toBe(true);
    expect(parsed.data?.agents.triage.access?.secrets).toEqual(['ANTHROPIC_API_KEY', 'SHOP_SIGNING_KEY']);
  });

  it('accepts an empty agent allowlist (no secrets at all)', () => {
    expect(AgentsYamlSchema.safeParse({
      version: 1,
      agents: { reader: { skill: 'read-only', access: { secrets: [] } } },
    }).success).toBe(true);
  });

  it('rejects an agent allowlist that is not a list of secret names', () => {
    for (const secrets of ['ANTHROPIC_API_KEY', [''], ['HAS SPACE'], [42]]) {
      expect(AgentsYamlSchema.safeParse({
        version: 1,
        agents: { triage: { skill: 'x', access: { secrets } } },
      }).success).toBe(false);
    }
  });

  it('accepts secrets on a workflow agent step and rejects a malformed one', () => {
    expect(WorkflowStepSchema.safeParse({ agent: { name: 'triage' }, secrets: ['SHOP_SIGNING_KEY'] }).success).toBe(true);
    expect(WorkflowStepSchema.safeParse({ agent: { name: 'triage' }, secrets: 'SHOP_SIGNING_KEY' }).success).toBe(false);
  });

  it('rejects secrets on a non-agent workflow step, where nothing would apply it', () => {
    const parsed = WorkflowStepSchema.safeParse({ script: { run: 'echo hi' }, secrets: ['A'] });
    expect(parsed.success).toBe(false);
    expect(parsed.error?.issues.map((issue) => issue.message).join('\n')).toContain('agent steps');
  });
});
