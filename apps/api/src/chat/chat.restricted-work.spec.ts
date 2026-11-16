import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { ChatService } from './chat.service.js';
import type { Db } from '@eve/db';
import type { JobsService } from '../jobs/jobs.service.js';
import type { RbacService } from '../auth/rbac.service.js';
import type { AuthUser } from '../auth/auth.types.js';

const RESTRICTED: AuthUser = {
  user_id: 'user_owner', is_job_token: true, job_id: 'opps-1', project_id: 'proj_opps',
  permissions: ['threads:write', 'chat:write'], secrets_allowlist: ['ANTHROPIC_API_KEY'],
} as AuthUser;

type Priv = {
  createChatJob(ctx: { user?: AuthUser } | undefined, projectId: string, data: Record<string, unknown>): Promise<{ id: string }>;
};

function serviceWith(create: ReturnType<typeof vi.fn>): Priv {
  return new ChatService(
    (() => ({})) as unknown as Db,
    { create } as unknown as JobsService,
    {} as RbacService,
  ) as unknown as Priv;
}

describe('jobs chat starts', () => {
  it('carry the allowlist of a restricted caller, as every other route that starts work', async () => {
    const create = vi.fn(async () => ({ id: 'opps-2' }));

    await serviceWith(create).createChatJob({ user: RESTRICTED }, 'proj_opps', { description: 'hi' });

    expect(create).toHaveBeenCalledWith('proj_opps', { description: 'hi' }, undefined, undefined, { secretsAllowlist: ['ANTHROPIC_API_KEY'] });
  });

  it('carry nothing for an unrestricted caller or a gateway dispatch', async () => {
    const create = vi.fn(async () => ({ id: 'opps-3' }));

    await serviceWith(create).createChatJob({ user: { user_id: 'user_owner' } }, 'proj_opps', { description: 'hi' });
    await serviceWith(create).createChatJob(undefined, 'proj_opps', { description: 'hi' });

    expect(create).toHaveBeenNthCalledWith(1, 'proj_opps', { description: 'hi' }, undefined, undefined, {});
    expect(create).toHaveBeenNthCalledWith(2, 'proj_opps', { description: 'hi' }, undefined, undefined, {});
  });

  it('are all created through createChatJob', () => {
    const source = readFileSync(join(__dirname, 'chat.service.ts'), 'utf8');
    expect(source.match(/this\.jobsService\.create\(/g)).toHaveLength(1);
  });
});
