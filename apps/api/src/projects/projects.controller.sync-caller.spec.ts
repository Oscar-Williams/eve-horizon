import { describe, expect, it, vi } from 'vitest';
import { ProjectsController } from './projects.controller';
import type { ProjectsService } from './projects.service';
import type { AuthUser } from '../auth/auth.types';

describe('ProjectsController manifest sync', () => {
  it('passes the caller to the sync, which judges sign-in org changes by it', async () => {
    const syncManifest = vi.fn(async () => ({ id: 'manifest_1' }));
    const controller = new ProjectsController({ syncManifest } as unknown as ProjectsService);
    const caller: AuthUser = { user_id: 'user_admin' };
    await controller.syncManifest('proj_a', { yaml: 'name: x' } as never, caller);
    expect(syncManifest).toHaveBeenCalledWith('proj_a', { yaml: 'name: x' }, caller);
  });
});
