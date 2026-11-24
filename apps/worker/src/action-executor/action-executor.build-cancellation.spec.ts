import { afterEach, describe, expect, it, vi } from 'vitest';
import { ActionExecutorService } from './action-executor.service.js';

afterEach(() => vi.useRealTimers());
describe('build action cancellation', () => {
  it.each(['job', 'build'])('observes %s cancellation and publishes no artifacts', async (source) => {
    vi.useFakeTimers();
    let cancelled = false;
    const builder = { backendName: 'sandbox', buildAll: vi.fn(async () => {
      cancelled = true;
      return { imageDigests: { web: 'sha256:result' } };
    }) };
    const service: any = new ActionExecutorService(null as any, {} as any, builder as any);
    service.jobs = { findById: vi.fn(async () => ({ phase: cancelled && source === 'job' ? 'cancelled' : 'active' })) };
    service.projects = { findById: vi.fn(async () => ({ repo_url: 'https://github.com/example/shop.git' })) };
    service.manifests = { findByProjectAndHash: vi.fn(async () => ({ manifest_yaml: 'registry:\n  host: registry.example.com\nservices:\n  web:\n    image: web\n    build:\n      context: .\n' })) };
    service.builds = {
      createSpec: vi.fn(async () => ({ id: 'bld_1' })), createRun: vi.fn(async () => ({ id: 'run_1' })),
      findRunById: vi.fn(async () => ({ status: cancelled && source === 'build' ? 'cancelled' : 'running' })),
      appendLog: vi.fn(), updateRun: vi.fn(), createArtifact: vi.fn(),
    };
    service.appendLog = vi.fn(); service.prepareWorkspace = vi.fn(async () => '/workspace');
    service.autoSyncManifestFromWorkspace = vi.fn(); service.cleanupWorkspace = vi.fn();
    await expect(service.handleBuild('attempt', 'proj_shop', { git_sha: 'abc', manifest_hash: 'mh', force_rebuild: true }, 'job_1')).rejects.toThrow('job_cancelled');
    expect(builder.buildAll).toHaveBeenCalledWith(expect.objectContaining({ signal: expect.any(AbortSignal) }));
    expect(service.builds.createArtifact).not.toHaveBeenCalled();
    expect(service.builds.updateRun).toHaveBeenCalledWith('run_1', expect.objectContaining({ status: 'cancelled' }));
    expect(service.cleanupWorkspace).toHaveBeenCalledWith('/workspace');
    const calls = service.jobs.findById.mock.calls.length;
    await vi.advanceTimersByTimeAsync(5_000);
    expect(service.jobs.findById).toHaveBeenCalledTimes(calls);
  });
});
