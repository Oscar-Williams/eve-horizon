import { afterEach, describe, expect, it, vi } from 'vitest';
import { handleRelease } from '../src/commands/release';

vi.mock('../src/lib/client', () => ({
  requestJson: vi.fn(),
  requestRaw: vi.fn(),
}));

import { requestJson, requestRaw } from '../src/lib/client';

const context = {
  apiUrl: 'http://example.test',
  token: 'token',
  profile: null,
  profileName: null,
  projectId: 'proj_shop',
};

const refusal = 'Release with tag "v1" is the current or last applied release of environment(s) prod';

/** The API refuses (409) to delete a release an environment runs; the CLI must not say it deleted it. */
describe('eve release delete', () => {
  afterEach(() => {
    vi.mocked(requestJson).mockReset();
    vi.mocked(requestRaw).mockReset();
    vi.restoreAllMocks();
  });

  it('fails with the API\'s refusal when an environment runs the release', async () => {
    vi.mocked(requestRaw).mockResolvedValue({
      status: 409, ok: false, data: { message: refusal }, text: JSON.stringify({ message: refusal }), headers: new Headers(),
    });
    vi.mocked(requestJson).mockRejectedValue(new Error(`HTTP 409: while calling DELETE /projects/proj_shop/releases/by-tag/v1: ${refusal}`));
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});

    await expect(handleRelease('delete', ['v1'], {}, context as never)).rejects.toThrow(/environment\(s\) prod/);
    expect(log.mock.calls.flat().join('\n')).not.toMatch(/deleted/);
  });

  it('says it deleted a release the API deleted', async () => {
    vi.mocked(requestRaw).mockResolvedValue({ status: 204, ok: true, data: null, text: '', headers: new Headers() });
    vi.mocked(requestJson).mockResolvedValue(null);
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});

    await handleRelease('delete', ['v1'], {}, context as never);

    expect(log.mock.calls.flat().join('\n')).toMatch(/Release v1 deleted/);
  });
});
