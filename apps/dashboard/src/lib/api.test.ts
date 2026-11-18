import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('@eve-horizon/auth-react', () => ({ getStoredToken: () => 'platform-token' }));

import { createEventSource } from './api';

/** Every URL the browser was asked to open, by EventSource or fetch, and the headers sent. */
const opened: Array<{ url: string; headers: Record<string, string> }> = [];

class RecordingEventSource {
  onmessage: ((event: { data: string }) => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) {
    opened.push({ url, headers: {} });
  }
  close(): void {}
}

function sseBody(events: string[]): ReadableStream<Uint8Array> {
  const encoder = new TextEncoder();
  return new ReadableStream({
    start(controller) {
      for (const data of events) controller.enqueue(encoder.encode(`data: ${data}\n\n`));
      controller.close();
    },
  });
}

beforeEach(() => {
  opened.length = 0;
  vi.stubGlobal('EventSource', RecordingEventSource);
  vi.stubGlobal('fetch', vi.fn(async (url: string, init: RequestInit = {}) => {
    const headers: Record<string, string> = {};
    new Headers(init.headers ?? {}).forEach((value, key) => { headers[key] = value; });
    opened.push({ url: String(url), headers });
    return new Response(sseBody(['{"logs":[]}']), { headers: { 'content-type': 'text/event-stream' } });
  }));
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('createEventSource (job log stream)', () => {
  it('keeps the platform token out of the stream URL and sends it as a header', async () => {
    const source = createEventSource('/jobs/job-1/stream');
    await vi.waitFor(() => expect(opened.length).toBeGreaterThan(0));

    for (const { url } of opened) {
      expect(url).not.toContain('platform-token');
      expect(url).not.toContain('token=');
    }
    expect(opened[0]).toEqual({
      url: '/api/jobs/job-1/stream',
      headers: expect.objectContaining({ authorization: 'Bearer platform-token' }),
    });
    source.close();
  });

  it('delivers each event to onmessage', async () => {
    const source = createEventSource('/jobs/job-1/stream');
    const received: string[] = [];
    source.onmessage = (event) => { received.push(event.data); };
    await vi.waitFor(() => expect(received).toEqual(['{"logs":[]}']));
    source.close();
  });
});
