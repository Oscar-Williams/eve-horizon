import { afterEach, describe, expect, it, vi } from 'vitest';
import { InvokeService } from './invoke.service.js';
import { buildToolchainRuntimeMeta } from './toolchains.js';

const previous = { image: process.env.EVE_RUNNER_IMAGE, db: process.env.DATABASE_URL };
afterEach(() => {
  if (previous.image === undefined) delete process.env.EVE_RUNNER_IMAGE;
  else process.env.EVE_RUNNER_IMAGE = previous.image;
  if (previous.db === undefined) delete process.env.DATABASE_URL;
  else process.env.DATABASE_URL = previous.db;
});

describe('agent-runtime toolchain metadata', () => {
  it('keeps pulled image IDs through provisioning and failure metadata writes', async () => {
    const prior = process.env.EVE_TOOLCHAIN_INIT_MOUNTED;
    process.env.EVE_TOOLCHAIN_INIT_MOUNTED = 'true';
    const imageIds = { browser: 'docker-pullable://browser@sha256:abc' };
    const runtimeMeta: Record<string, unknown> = { toolchains: {
      requested: ['browser'], resolved: ['browser'], image_ids: imageIds,
    } };
    const db = vi.fn(async () => [{ runtime_meta: runtimeMeta }]);
    const service = new InvokeService(db as never);
    const updateRuntimeMeta = vi.fn(async (_id: string, update: Record<string, unknown>) => {
      Object.assign(runtimeMeta, update);
    });
    (service as unknown as { jobs: unknown }).jobs = { updateRuntimeMeta };
    const write = (service as unknown as { updateToolchainRuntimeMeta: (id: string, value: ReturnType<typeof buildToolchainRuntimeMeta>) => Promise<void> }).updateToolchainRuntimeMeta.bind(service);
    try {
      await write('00000000-0000-0000-0000-000000000001', buildToolchainRuntimeMeta({
        executionMode: 'inline', requested: ['browser'], resolved: ['browser'],
      }));
      await write('00000000-0000-0000-0000-000000000001', buildToolchainRuntimeMeta({
        executionMode: 'inline', requested: ['browser'], source: 'unavailable',
        errorCode: 'toolchain_unavailable', error: 'browser launch failed',
      }));
      expect(runtimeMeta.toolchains).toMatchObject({
        image_ids: imageIds, error_code: 'toolchain_unavailable', error: 'browser launch failed',
      });
      expect(updateRuntimeMeta).toHaveBeenCalledTimes(2);
    } finally {
      if (prior === undefined) delete process.env.EVE_TOOLCHAIN_INIT_MOUNTED;
      else process.env.EVE_TOOLCHAIN_INIT_MOUNTED = prior;
    }
  });
});
