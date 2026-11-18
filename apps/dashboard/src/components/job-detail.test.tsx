// @vitest-environment jsdom
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const JOB = {
  id: 'job-1',
  project_id: 'proj_a',
  title: 'Draft the summary',
  phase: 'review',
  priority: 2,
  review_required: 'human',
  review_status: 'pending',
  labels: [],
  created_at: '2026-11-18T09:00:00Z',
  updated_at: '2026-11-18T09:00:00Z',
};

const calls = vi.hoisted(() => [] as Array<{ path: string; init?: { method?: string; body?: string } }>);

vi.mock('@/lib/api', () => ({
  api: vi.fn(async (path: string, init?: { method?: string; body?: string }) => {
    calls.push({ path, init });
    if (path === '/jobs/job-1') return JOB;
    if (path === '/jobs/job-1/attempts') return { attempts: [] };
    return {};
  }),
  createEventSource: vi.fn(),
  ApiError: class ApiError extends Error {
    constructor(
      public status: number,
      public body: string,
    ) {
      super(`API ${status}: ${body}`);
    }
  },
}));

import { JobDetail } from './job-detail';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

let container: HTMLDivElement;
let root: Root;

async function render(): Promise<void> {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  await act(async () => {
    root.render(
      <QueryClientProvider client={client}>
        <JobDetail job={JOB as never} onClose={() => undefined} />
      </QueryClientProvider>,
    );
  });
}

async function click(label: string): Promise<void> {
  const button = Array.from(container.querySelectorAll('button')).find((b) => b.textContent?.trim() === label);
  if (!button) throw new Error(`${label} button not rendered`);
  await act(async () => {
    button.dispatchEvent(new MouseEvent('click', { bubbles: true }));
  });
}

function reviewCalls() {
  return calls.filter((c) => c.init?.method === 'POST');
}

beforeEach(() => {
  calls.length = 0;
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  vi.unstubAllGlobals();
});

describe('JobDetail review buttons', () => {
  it('approve through the approve route, naming no reviewer', async () => {
    await render();
    await click('Approve');

    expect(reviewCalls()).toEqual([{ path: '/jobs/job-1/approve', init: { method: 'POST', body: '{}' } }]);
  });

  it('reject through the reject route with the reason given', async () => {
    vi.stubGlobal('prompt', vi.fn(() => 'Cite the sources'));
    await render();
    await click('Reject');

    expect(reviewCalls()).toEqual([
      { path: '/jobs/job-1/reject', init: { method: 'POST', body: JSON.stringify({ reason: 'Cite the sources' }) } },
    ]);
  });

  it('send nothing when no rejection reason is given', async () => {
    vi.stubGlobal('prompt', vi.fn(() => null));
    await render();
    await click('Reject');

    expect(reviewCalls()).toEqual([]);
  });
});
