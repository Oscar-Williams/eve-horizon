import { describe, expect, it } from 'vitest';
import { buildEveAgentCliArgs, spawnHarnessProcess } from '../harness-process.js';

const PROMPT = 'Triage notice 4471: untrusted text from a tender portal';

// A stand-in harness: reports what it received on argv and on stdin.
const PROBE = [
  '-e',
  `let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{process.stdout.write(JSON.stringify({argv:process.argv,stdin:s}));});`,
];

function collect(child: ReturnType<typeof spawnHarnessProcess>): Promise<{ argv: string[]; stdin: string }> {
  return new Promise((resolve, reject) => {
    let out = '';
    child.stdout.on('data', (chunk) => { out += chunk; });
    child.on('error', reject);
    child.on('close', () => {
      try { resolve(JSON.parse(out)); } catch (error) { reject(error); }
    });
  });
}

describe('harness process launch', () => {
  it('keeps the prompt off the eve-agent-cli command line', () => {
    const args = buildEveAgentCliArgs({
      harness: 'claude',
      permission: 'yolo',
      workspace: '/workspace/repo',
      model: 'claude-sonnet-5-5',
    });

    expect(args).not.toContain('--prompt');
    expect(args.join(' ')).not.toContain(PROMPT);
    expect(args).toEqual(expect.arrayContaining(['--harness', 'claude', '--model', 'claude-sonnet-5-5']));
  });

  it('hands the prompt to the harness on stdin, not argv', async () => {
    const child = spawnHarnessProcess(process.execPath, PROBE, {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH },
      prompt: PROMPT,
    });

    const seen = await collect(child);

    expect(seen.stdin).toBe(PROMPT);
    expect(seen.argv.join(' ')).not.toContain(PROMPT);
  });

  it('survives a harness that exits without reading its prompt', async () => {
    const child = spawnHarnessProcess(process.execPath, ['-e', 'process.exit(3)'], {
      cwd: process.cwd(),
      env: { PATH: process.env.PATH },
      prompt: 'x'.repeat(1024 * 1024),
    });

    const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
    expect(code).toBe(3);
  });
});
