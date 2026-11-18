import { getStoredToken } from '@eve-horizon/auth-react';

const BASE = '/api';

function headers(): Record<string, string> {
  const h: Record<string, string> = { 'Content-Type': 'application/json' };
  const token = getStoredToken();
  if (token) h['Authorization'] = `Bearer ${token}`;
  return h;
}

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: { ...headers(), ...init?.headers },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, text);
  }
  return res.json() as Promise<T>;
}

export class ApiError extends Error {
  constructor(
    public status: number,
    public body: string,
  ) {
    super(`API ${status}: ${body}`);
    this.name = 'ApiError';
  }
}

/** A server-sent event stream, read with fetch so the token goes in a header. */
export interface ApiEventStream {
  onmessage: ((event: { data: string }) => void) | null;
  onerror: (() => void) | null;
  close(): void;
}

/**
 * Stream server-sent events from the API (job logs). EventSource cannot send
 * an Authorization header, and a token in the URL would be logged, so the
 * stream is read with fetch. `onerror` fires once when the stream fails or
 * ends; the caller reconnects.
 */
export function createEventSource(path: string): ApiEventStream {
  const controller = new AbortController();
  const stream: ApiEventStream = {
    onmessage: null,
    onerror: null,
    close: () => controller.abort(),
  };

  void (async () => {
    try {
      const res = await fetch(`${BASE}${path}`, {
        headers: { ...headers(), Accept: 'text/event-stream' },
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new ApiError(res.status, res.statusText);
      const reader = res.body.pipeThrough(new TextDecoderStream()).getReader();
      let buffer = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += value.replace(/\r\n?/g, '\n');
        let end: number;
        while ((end = buffer.indexOf('\n\n')) >= 0) {
          const block = buffer.slice(0, end);
          buffer = buffer.slice(end + 2);
          const data = block
            .split('\n')
            .filter((line) => line.startsWith('data:'))
            .map((line) => line.slice(5).replace(/^ /, ''))
            .join('\n');
          if (data) stream.onmessage?.({ data });
        }
      }
    } catch {
      // Reported below unless the caller closed the stream.
    }
    if (!controller.signal.aborted) stream.onerror?.();
  })();

  return stream;
}
