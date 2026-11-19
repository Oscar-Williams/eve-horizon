import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ decide: vi.fn() }));

vi.mock('@eve/db', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@eve/db')>()),
  decideSecurityRule: mocks.decide,
}));

import { reservedEnvOverridesStrict } from './reserved-env.js';

const job = (env_overrides: Record<string, string> | null) => ({
  id: 'lab-1', project_id: 'proj_lab', actor_user_id: 'user_alice', env_overrides,
});

beforeEach(() => {
  vi.clearAllMocks();
});

describe('reserved env overrides a stored script or action job carries', () => {
  it('decide nothing when the job carries none', async () => {
    await expect(reservedEnvOverridesStrict(null as never, job({ FOO: 'bar' }))).resolves.toBe(false);
    expect(mocks.decide).not.toHaveBeenCalled();
  });

  it('are recorded, and stripped only under strict', async () => {
    mocks.decide.mockResolvedValueOnce('audit').mockResolvedValueOnce('strict');

    await expect(reservedEnvOverridesStrict(null as never, job({ PYTHONPATH: '/opt/lib' }))).resolves.toBe(false);
    await expect(reservedEnvOverridesStrict(null as never, job({ PYTHONPATH: '/opt/lib' }))).resolves.toBe(true);

    expect(mocks.decide).toHaveBeenCalledWith(null, 'harness.reserved_env', expect.objectContaining({
      projectId: 'proj_lab',
      governing: 'project',
      detail: expect.objectContaining({ job_id: 'lab-1', keys: 'PYTHONPATH' }),
    }));
  });
});
