import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const state = vi.hoisted(() => ({ decide: vi.fn() }));
vi.mock('@eve/db', async (original) => ({ ...await original<any>(), decideSecurityRule: state.decide }));
import { ImageBuilderService } from '../image-builder.service.js';

const params = {
  manifest: {} as any,
  manifestYaml: 'registry: eve\nservices:\n  web:\n    image: web\n    build:\n      context: .\n',
  projectId: 'proj_shop', gitSha: 'abc123', workspacePath: '/workspace',
};
let auth: any;
let builder: any;

beforeEach(() => {
  state.decide.mockReset().mockResolvedValue('audit');
  auth = { resolve: vi.fn().mockResolvedValue({
    auth: { host: 'registry.example.com', dockerConfigJson: 'e30=' },
    config: { host: 'registry.example.com', eveProjectId: 'proj_shop' },
  }) };
  builder = { kind: 'buildkit', buildService: vi.fn().mockResolvedValue('sha256:result'), buildAll: vi.fn() };
});
afterEach(() => vi.unstubAllEnvs());
const service = () => new (ImageBuilderService as any)(auth, builder, {});

describe('build backend policy', () => {
  it('refuses the shared backend under the instance rule before resolving credentials', async () => {
    state.decide.mockResolvedValue('strict');
    await expect(service().buildAll(params)).rejects.toThrow(/builds.isolated/);
    expect(auth.resolve).not.toHaveBeenCalled();
    expect(builder.buildService).not.toHaveBeenCalled();
    expect(state.decide).toHaveBeenCalledWith(expect.anything(), 'builds.isolated', expect.objectContaining({ governing: 'instance', projectId: 'proj_shop' }));
  });

  it('records shared builds under audit and preserves their behavior', async () => {
    await service().buildAll(params);
    expect(state.decide).toHaveBeenCalledOnce();
    expect(builder.buildService).toHaveBeenCalledOnce();
  });

  it('passes project identity and cancellation into the isolated backend without a finding', async () => {
    builder.kind = 'sandbox';
    const controller = new AbortController();
    await service().buildAll({ ...params, signal: controller.signal });
    expect(state.decide).not.toHaveBeenCalled();
    expect(builder.buildService).toHaveBeenCalledWith(expect.objectContaining({ projectId: 'proj_shop', signal: controller.signal }));
  });

  it('does not acquire credentials for a cancelled build', async () => {
    const controller = new AbortController(); controller.abort(new Error('cancelled build'));
    await expect(service().buildAll({ ...params, signal: controller.signal })).rejects.toThrow(/cancelled build/);
    expect(auth.resolve).not.toHaveBeenCalled();
  });
});
