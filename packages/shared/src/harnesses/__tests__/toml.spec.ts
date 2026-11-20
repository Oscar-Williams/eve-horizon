import { describe, expect, it } from 'vitest';
import { parseToml } from '../toml.js';

/**
 * The TOML reader rule harness.checkout_settings uses on Codex configs. It
 * must see every key a config sets, whatever form sets it (tables, dotted
 * keys, inline tables, quoted keys), and never mistake text inside a string
 * or a comment for a key. Input it cannot read throws.
 */
describe('parseToml', () => {
  it('reads tables, dotted keys, inline tables and quoted keys into one tree', () => {
    const doc = parseToml([
      'model = "gpt-5.5"  # the default',
      'profile = "fast"',
      'profiles.slow.model = "o3"',
      '"quoted key" = 1',
      '',
      '[ profiles . "my fast" ]',
      "model_provider = 'relay'",
      '',
      '[model_providers]',
      'relay = { name = "Relay", base_url = "https://relay.eve.example/v1", headers = { "x-shop" = "acme" } }',
      '',
      '[[mcp_servers.docs.args]]',
      'value = "--port"',
      '[[mcp_servers.docs.args]]',
      'value = "8080"',
    ].join('\n'));
    expect(doc).toEqual({
      model: 'gpt-5.5',
      profile: 'fast',
      profiles: { slow: { model: 'o3' }, 'my fast': { model_provider: 'relay' } },
      'quoted key': 1,
      model_providers: { relay: { name: 'Relay', base_url: 'https://relay.eve.example/v1', headers: { 'x-shop': 'acme' } } },
      mcp_servers: { docs: { args: [{ value: '--port' }, { value: '8080' }] } },
    });
  });

  it('keeps headers, assignments and comments inside strings as text', () => {
    const doc = parseToml([
      'instructions = """',
      '[model_providers.fake]',
      'base_url = "https://relay.eve.example" # not a comment',
      '"""',
      "notes = '''",
      "model_provider = 'x'",
      "'''",
      'hash = "a # b \\" c"',
      "path = 'C:\\temp'",
      'multi = """one \\',
      '   two"""',
    ].join('\n'));
    expect(Object.keys(doc)).toEqual(['instructions', 'notes', 'hash', 'path', 'multi']);
    expect(doc.instructions).toBe('[model_providers.fake]\nbase_url = "https://relay.eve.example" # not a comment\n');
    expect(doc.hash).toBe('a # b " c');
    expect(doc.path).toBe('C:\\temp');
    expect(doc.multi).toBe('one two');
  });

  it('reads numbers, booleans, dates and arrays across lines', () => {
    const doc = parseToml([
      'ints = [ 1, -2, +3, 1_000, 0x1F, 0o17, 0b101 ]',
      'floats = [ 1.5, -0.25e3, inf, -inf, nan ]',
      'flags = [ true, false ]',
      'when = 2026-11-20T10:00:00Z',
      'local = 2026-11-20 10:00:00.5',
      'day = 2026-11-20',
      'clock = 07:32:00',
      'nested = [',
      '  [ "a", "b" ],  # a comment',
      '  [ { k = "v" } ],',
      ']',
    ].join('\n'));
    expect(doc.ints).toEqual([1, -2, 3, 1000, 31, 15, 5]);
    expect((doc.floats as number[]).slice(0, 4)).toEqual([1.5, -250, Infinity, -Infinity]);
    expect(Number.isNaN((doc.floats as number[])[4])).toBe(true);
    expect(doc.flags).toEqual([true, false]);
    expect(doc.when).toBe('2026-11-20T10:00:00Z');
    expect(doc.local).toBe('2026-11-20 10:00:00.5');
    expect(doc.day).toBe('2026-11-20');
    expect(doc.clock).toBe('07:32:00');
    expect(doc.nested).toEqual([['a', 'b'], [{ k: 'v' }]]);
  });

  it('reads escapes in basic strings', () => {
    expect(parseToml('s = "tab\\tnew\\nu\\u00e9U\\U0001F600"').s).toBe('tab\tnew\nu\u00e9U\u{1F600}');
  });

  it('throws on input it cannot read', () => {
    for (const bad of [
      'key = "unterminated',
      'key = """never closed',
      'no equals sign',
      '[unclosed',
      'key = ',
      'key = [1, 2',
      'key = { a = 1',
      'key = 1 2',
      'a.b = 1\na = 2',
      '= 1',
    ]) {
      expect(() => parseToml(bad), bad).toThrow();
    }
  });
});
