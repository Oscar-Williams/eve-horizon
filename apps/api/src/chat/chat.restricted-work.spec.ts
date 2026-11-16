import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
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
  createChatJob(projectId: string, data: Record<string, unknown>, ctx?: { user?: AuthUser }): Promise<{ id: string }>;
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

    await serviceWith(create).createChatJob('proj_opps', { description: 'hi' }, { user: RESTRICTED });

    expect(create).toHaveBeenCalledWith('proj_opps', { description: 'hi' }, undefined, undefined, { secretsAllowlist: ['ANTHROPIC_API_KEY'] });
  });

  it('carry nothing for an unrestricted caller or a gateway dispatch', async () => {
    const create = vi.fn(async () => ({ id: 'opps-3' }));

    await serviceWith(create).createChatJob('proj_opps', { description: 'hi' }, { user: { user_id: 'user_owner' } });
    await serviceWith(create).createChatJob('proj_opps', { description: 'hi' });

    expect(create).toHaveBeenNthCalledWith(1, 'proj_opps', { description: 'hi' }, undefined, undefined, {});
    expect(create).toHaveBeenNthCalledWith(2, 'proj_opps', { description: 'hi' }, undefined, undefined, {});
  });

  it('are all created through createChatJob', () => {
    const source = readFileSync(fileURLToPath(new URL('./chat.service.ts', import.meta.url)), 'utf8');
    expect(source.match(/this\.jobsService\.create\(/g)).toHaveLength(1);
  });
});
