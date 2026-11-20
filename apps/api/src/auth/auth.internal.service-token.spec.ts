import { NotFoundException } from '@nestjs/common';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { DEFAULT_SERVICE_PERMISSIONS } from '@eve/shared';
import { AuthInternalController } from './auth.internal.controller.js';

/**
 * A service token grants at most the read-only defaults plus the service's
 * `x-eve.permissions` from the manifest of the release deployed to the env,
 * whatever the request asks for. The env must exist in the project, and the
 * project in the org.
 */
const MANIFEST_V1 = `
services:
  api:
    image: shop/api
    x-eve:
      permissions: [jobs:write]
  web:
    image: shop/web
`;
const MANIFEST_V2 = `
services:
  api:
    image: shop/api
    x-eve:
      permissions: [jobs:write, threads:write]
`;

describe('mint-service-token', () => {
  const mintServiceToken = vi.fn((params: { permissions: string[] }) => {
    const payload = Buffer.from(JSON.stringify({ exp: 1_900_000_000, permissions: params.permissions })).toString('base64url');
    return `h.${payload}.s`;
  });
  let controller: AuthInternalController;
  let env: {
    id: string;
    current_release_id: string | null;
    last_applied_release_id: string | null;
    created_at?: Date;
    service_tokens_not_before?: Date | null;
  } | null;

  beforeEach(() => {
    mintServiceToken.mockClear();
    env = { id: 'env_test', current_release_id: 'rel_v1', last_applied_release_id: 'rel_v1' };
    controller = new AuthInternalController({ mintServiceToken } as never, null as never, {} as never);
    Object.assign(controller as object, {
      projects: { findById: vi.fn(async (id: string) => (id === 'proj_shop' ? { id, org_id: 'org_acme' } : null)) },
      environments: {
        findByProjectAndName: vi.fn(async (projectId: string, name: string) =>
          (projectId === 'proj_shop' && name === 'test' ? env : null)),
      },
      releases: {
        findById: vi.fn(async (id: string) => ({
          rel_v1: { id, project_id: 'proj_shop', manifest_hash: 'hash_v1' },
          rel_v2: { id, project_id: 'proj_shop', manifest_hash: 'hash_v2' },
          rel_other: { id, project_id: 'proj_other', manifest_hash: 'hash_other' },
        } as Record<string, unknown>)[id] ?? null),
      },
      manifests: {
        findByProjectAndHash: vi.fn(async (projectId: string, hash: string) => {
          if (projectId !== 'proj_shop') return null;
          if (hash === 'hash_v1') return { manifest_yaml: MANIFEST_V1 };
          if (hash === 'hash_v2') return { manifest_yaml: MANIFEST_V2 };
          return null;
        }),
      },
    });
  });

  const body = (overrides: Record<string, unknown> = {}) => ({
    project_id: 'proj_shop',
    org_id: 'org_acme',
    env_name: 'test',
    service_name: 'api',
    permissions: [...DEFAULT_SERVICE_PERMISSIONS, 'jobs:write'],
    ...overrides,
  });
  const granted = () => mintServiceToken.mock.calls.at(-1)![0].permissions;

  it('clamps a request for secrets:write that the manifest does not declare', async () => {
    await controller.mintServiceToken(body({ permissions: [...DEFAULT_SERVICE_PERMISSIONS, 'jobs:write', 'secrets:write', 'orgs:admin'] }));
    expect(granted()).toEqual([...DEFAULT_SERVICE_PERMISSIONS, 'jobs:write']);
  });

  it('grants the defaults when the request names no permissions', async () => {
    await controller.mintServiceToken(body({ permissions: undefined }));
    expect(granted()).toEqual([...DEFAULT_SERVICE_PERMISSIONS]);
  });

  it('gives a service the manifest declares no permissions for only the defaults', async () => {
    await controller.mintServiceToken(body({ service_name: 'web' }));
    expect(granted()).toEqual([...DEFAULT_SERVICE_PERMISSIONS]);
  });

  it('reads the manifest of the release being deployed when the worker names it', async () => {
    await controller.mintServiceToken(body({
      release_id: 'rel_v2',
      permissions: [...DEFAULT_SERVICE_PERMISSIONS, 'jobs:write', 'threads:write'],
    }));
    expect(granted()).toEqual([...DEFAULT_SERVICE_PERMISSIONS, 'jobs:write', 'threads:write']);
  });

  it('refuses a release of another project', async () => {
    await expect(controller.mintServiceToken(body({ release_id: 'rel_other' }))).rejects.toThrow(NotFoundException);
    expect(mintServiceToken).not.toHaveBeenCalled();
  });

  it('gives only the defaults to an env with no release yet and none named', async () => {
    env = { id: 'env_test', current_release_id: null, last_applied_release_id: null };
    await controller.mintServiceToken(body());
    expect(granted()).toEqual([...DEFAULT_SERVICE_PERMISSIONS]);
  });

  it('refuses an env outside the project and a project outside the org', async () => {
    await expect(controller.mintServiceToken(body({ env_name: 'staging' }))).rejects.toThrow(NotFoundException);
    await expect(controller.mintServiceToken(body({ org_id: 'org_other' }))).rejects.toThrow(NotFoundException);
    await expect(controller.mintServiceToken(body({ project_id: 'proj_missing' }))).rejects.toThrow(NotFoundException);
    expect(mintServiceToken).not.toHaveBeenCalled();
  });

  it('mints no earlier than the environment\'s floor: its service_tokens_not_before, or its creation', async () => {
    const ahead = Math.floor(Date.now() / 1000) + 5;
    env = {
      id: 'env_test',
      current_release_id: 'rel_v1',
      last_applied_release_id: 'rel_v1',
      created_at: new Date((ahead - 60) * 1000),
      service_tokens_not_before: new Date(ahead * 1000 + 400),
    };
    await controller.mintServiceToken(body());
    expect(mintServiceToken.mock.calls.at(-1)![0]).toEqual(expect.objectContaining({ notBefore: ahead }));

    env = { ...env, created_at: new Date(ahead * 1000), service_tokens_not_before: null };
    await controller.mintServiceToken(body());
    expect(mintServiceToken.mock.calls.at(-1)![0]).toEqual(expect.objectContaining({ notBefore: ahead }));
  });
});
