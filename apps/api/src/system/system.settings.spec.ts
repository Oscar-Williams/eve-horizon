import { beforeEach, describe, expect, it, vi } from 'vitest';
import { BadRequestException } from '@nestjs/common';
import { SystemController } from './system.controller';
import { SystemService } from './system.service';
import type { AuthUser } from '../auth/auth.types';

const settings = vi.hoisted(() => ({
  set: vi.fn(async (key: string, value: string, updatedBy: string) => ({ key, value, updated_by: updatedBy })),
  get: vi.fn(async () => null),
  list: vi.fn(async () => []),
  delete: vi.fn(async () => true),
}));

vi.mock('@eve/db', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@eve/db')>();
  return { ...actual, systemSettingsQueries: vi.fn(() => settings) };
});

describe('system settings', () => {
  beforeEach(() => vi.clearAllMocks());

  it('refuses a security profile setting that is not a profile', async () => {
    const svc = new SystemService({} as never);
    await expect(svc.setSetting('security.profile', 'enforce', 'user_admin')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(svc.setSetting('security.new_project_profile', '', 'user_admin')).rejects.toBeInstanceOf(
      BadRequestException,
    );
    expect(settings.set).not.toHaveBeenCalled();
  });

  it('accepts a security profile setting that is a profile', async () => {
    const svc = new SystemService({} as never);
    await svc.setSetting('security.profile', 'strict', 'user_admin');
    expect(settings.set).toHaveBeenCalledWith('security.profile', 'strict', 'user_admin', undefined);
  });

  it('records the system admin who changed a setting', async () => {
    const svc = new SystemService({} as never);
    const controller = new SystemController(svc);
    const admin: AuthUser = { user_id: 'user_admin', role: 'system_admin', is_admin: true };
    await controller.setSetting('harness_preference', { value: 'claude' }, admin);
    expect(settings.set).toHaveBeenCalledWith('harness_preference', 'claude', 'user_admin', undefined);
  });

  it('takes network.policy_enforced only as true or false', async () => {
    const svc = new SystemService({} as never);
    await expect(svc.setSetting('network.policy_enforced', 'yes', 'user_admin')).rejects.toThrow(/true or false/);
    await svc.setSetting('network.policy_enforced', 'true', 'user_admin');
    expect(settings.set).toHaveBeenCalledWith('network.policy_enforced', 'true', 'user_admin', undefined);
  });

  it('takes network.private_cidrs only as IPv4 CIDRs, naming the ones it cannot use', async () => {
    const svc = new SystemService({} as never);
    await expect(svc.setSetting('network.private_cidrs', '10.0.0.0/8, fd00::/8, nope', 'user_admin'))
      .rejects.toThrow(/fd00::\/8.*nope/);
    expect(settings.set).not.toHaveBeenCalled();
    await svc.setSetting('network.private_cidrs', '198.18.0.0/15', 'user_admin');
    expect(settings.set).toHaveBeenCalledWith('network.private_cidrs', '198.18.0.0/15', 'user_admin', undefined);
  });
});
