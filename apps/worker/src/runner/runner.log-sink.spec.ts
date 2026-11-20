import { describe, expect, it } from 'vitest';
import type { RunnerApiClient } from '@eve/shared';
import { RunnerLogSink } from './runner.executor.js';

/**
 * A runner pushes its execution logs to the attempt's logs route in batches.
 * The API takes JSON bodies up to 1 MiB, so a batch stays well under that
 * whatever its entries hold, and one entry too large on its own is cut down,
 * with a marker, rather than dropped with its batch.
 */
const LIMIT = 512 * 1024;

function sink() {
  const batches: Array<Array<{ type: string; content: Record<string, unknown> }>> = [];
  const client = { appendLogs: async (entries: Array<{ type: string; content: Record<string, unknown> }>) => { batches.push(entries); } };
  return { sink: new RunnerLogSink(client as unknown as RunnerApiClient), batches };
}

const bodySize = (entries: unknown) => Buffer.byteLength(JSON.stringify({ entries }));

describe('runner log batches', () => {
  it('splits a batch of large entries so each body stays well under the API limit, losing none', async () => {
    const { sink: logs, batches } = sink();
    for (let i = 0; i < 100; i += 1) logs.appendLog('assistant', { index: i, text: 'x'.repeat(50 * 1024) });
    await logs.flush();
    expect(batches.length).toBeGreaterThan(1);
    for (const batch of batches) expect(bodySize(batch)).toBeLessThanOrEqual(LIMIT);
    expect(batches.flat().map((entry) => entry.content.index)).toEqual([...Array(100).keys()]);
  });

  it('cuts down one entry too large on its own, and marks it', async () => {
    const { sink: logs, batches } = sink();
    logs.appendLog('tool_result', { tool: 'Bash', output: 'y'.repeat(2 * 1024 * 1024) });
    logs.appendLog('assistant', { text: 'after' });
    await logs.flush();
    const sent = batches.flat();
    expect(sent.map((entry) => entry.type)).toEqual(['tool_result', 'assistant']);
    expect(sent[0].content).toMatchObject({ tool: 'Bash', truncated: true });
    expect(bodySize([sent[0]])).toBeLessThanOrEqual(LIMIT);
    for (const batch of batches) expect(bodySize(batch)).toBeLessThanOrEqual(LIMIT);
  });

  it('still sends small entries a hundred at a time', async () => {
    const { sink: logs, batches } = sink();
    for (let i = 0; i < 150; i += 1) logs.appendLog('log', { line: `line ${i}` });
    await logs.flush();
    expect(batches.map((batch) => batch.length)).toEqual([100, 50]);
  });
});
