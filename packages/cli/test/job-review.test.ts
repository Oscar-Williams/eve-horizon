import { afterEach, describe, expect, it, vi } from 'vitest';
import { handleJob } from '../src/commands/job';

vi.mock('../src/lib/client', () => ({
  requestJson: vi.fn(),
  requestRaw: vi.fn(),
}));

import { requestJson } from '../src/lib/client';

const context = {
  apiUrl: 'http://example.test',
  token: 'token',
  profile: null,
  profileName: null,
  projectId: 'proj_a',
};

const reviewed = { id: 'job-1', phase: 'done', review_status: 'approved', reviewer: 'user_a' };

describe('eve job approve and reject', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.mocked(requestJson).mockReset();
  });

  it('approve sends the comment and no reviewer: the API records the caller', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce(reviewed);
    vi.spyOn(console, 'log').mockImplementation(() => undefined);

    await handleJob('approve', ['job-1'], { comment: 'Looks right' }, context as never);

    expect(requestJson).toHaveBeenCalledWith(context, '/jobs/job-1/approve', { method: 'POST', body: { comment: 'Looks right' } });
  });

  it('reject sends the reason and no reviewer', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce({ ...reviewed, phase: 'active', review_status: 'rejected' });
    vi.spyOn(console, 'log').mockImplementation(() => undefined);

    await handleJob('reject', ['job-1'], { reason: 'Cite the sources' }, context as never);

    expect(requestJson).toHaveBeenCalledWith(context, '/jobs/job-1/reject', { method: 'POST', body: { reason: 'Cite the sources' } });
  });
});
