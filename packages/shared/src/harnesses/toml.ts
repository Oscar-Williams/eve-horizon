/**
 * A small TOML reader, for rule harness.checkout_settings: it reads a Codex
 * `config.toml` from a checkout so every key the file sets is seen, whatever
 * form sets it (tables, array tables, dotted keys, inline tables, quoted
 * keys), and text inside strings or comments is never taken for a key.
 *
 * It reads TOML 1.0, and also takes inline tables over several lines with a
 * trailing comma (TOML 1.1). Dates and times come back as their text. It
 * does not check every rule a strict parser does (redefined tables, mixed
 * array types), since it only has to find keys; input it cannot read throws,
 * and the caller treats that as a finding rather than a clean file. Tables
 * have no prototype, so a key such as `__proto__` is an ordinary key.
 */

export type TomlValue = string | number | boolean | TomlValue[] | TomlTable;
export interface TomlTable {
  [key: string]: TomlValue;
}

export function parseToml(text: string): TomlTable {
  return new TomlReader(text).document();
}

const BARE_KEY = /[A-Za-z0-9_-]/;
const SCALAR = /[0-9A-Za-z_:.+-]/;
const ESCAPES: Record<string, string> = { b: '\b', t: '\t', n: '\n', f: '\f', r: '\r', e: '\x1b', '"': '"', '\\': '\\' };

function newTable(): TomlTable {
  return Object.create(null) as TomlTable;
}

function isTable(value: TomlValue | undefined): value is TomlTable {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

class TomlReader {
  private pos = 0;

  constructor(private readonly src: string) {}

  document(): TomlTable {
    const root = newTable();
    let current = root;
    for (;;) {
      this.skipBlank();
      if (this.eof()) return root;
      if (this.peek() === '[') {
        const array = this.peek(1) === '[';
        this.pos += array ? 2 : 1;
        const keys = this.keyPath();
        this.expect(array ? ']]' : ']');
        current = array ? this.arrayTable(root, keys) : this.tableAt(root, keys);
      } else {
        this.keyValue(current);
      }
      this.endOfLine();
    }
  }

  // ── Structure ────────────────────────────────────────────────────────

  private keyValue(table: TomlTable): void {
    const keys = this.keyPath();
    this.skipSpaces();
    this.expect('=');
    this.skipSpaces();
    const value = this.value();
    let target = table;
    for (const key of keys.slice(0, -1)) {
      const child = target[key];
      if (child === undefined) target = target[key] = newTable();
      else if (isTable(child)) target = child;
      else throw this.error(`key ${keys.join('.')} extends a value that is not a table`);
    }
    const last = keys[keys.length - 1];
    if (last in target) throw this.error(`key ${keys.join('.')} is set twice`);
    target[last] = value;
  }

  private tableAt(root: TomlTable, keys: string[]): TomlTable {
    let target = root;
    for (const key of keys) {
      const child = target[key];
      if (child === undefined) target = target[key] = newTable();
      else if (isTable(child)) target = child;
      else if (Array.isArray(child) && isTable(child[child.length - 1])) target = child[child.length - 1] as TomlTable;
      else throw this.error(`table ${keys.join('.')} redefines a value`);
    }
    return target;
  }

  private arrayTable(root: TomlTable, keys: string[]): TomlTable {
    const parent = this.tableAt(root, keys.slice(0, -1));
    const last = keys[keys.length - 1];
    const existing = parent[last];
    const array = existing === undefined ? (parent[last] = []) : existing;
    if (!Array.isArray(array)) throw this.error(`array table ${keys.join('.')} redefines a value`);
    const table = newTable();
    array.push(table);
    return table;
  }

  private keyPath(): string[] {
    const keys: string[] = [];
    for (;;) {
      this.skipSpaces();
      keys.push(this.simpleKey());
      this.skipSpaces();
      if (this.peek() !== '.') return keys;
      this.pos += 1;
    }
  }

  private simpleKey(): string {
    const c = this.peek();
    if (c === '"') return this.basicString();
    if (c === "'") return this.literalString();
    const start = this.pos;
    while (!this.eof() && BARE_KEY.test(this.peek())) this.pos += 1;
    if (this.pos === start) throw this.error('a key is missing');
    return this.src.slice(start, this.pos);
  }

  // ── Values ───────────────────────────────────────────────────────────

  private value(): TomlValue {
    const c = this.peek();
    if (c === '"') return this.src.startsWith('"""', this.pos) ? this.multilineString('"""') : this.basicString();
    if (c === "'") return this.src.startsWith("'''", this.pos) ? this.multilineString("'''") : this.literalString();
    if (c === '[') return this.array();
    if (c === '{') return this.inlineTable();
    return this.scalar();
  }

  private array(): TomlValue[] {
    this.pos += 1;
    const items: TomlValue[] = [];
    for (;;) {
      this.skipBlank();
      if (this.peek() === ']') {
        this.pos += 1;
        return items;
      }
      items.push(this.value());
      this.skipBlank();
      if (this.peek() === ',') this.pos += 1;
      else if (this.peek() !== ']') throw this.error('an array needs , or ]');
    }
  }

  private inlineTable(): TomlTable {
    this.pos += 1;
    const table = newTable();
    this.skipBlank();
    if (this.peek() === '}') {
      this.pos += 1;
      return table;
    }
    for (;;) {
      this.keyValue(table);
      this.skipBlank();
      if (this.peek() === '}') {
        this.pos += 1;
        return table;
      }
      if (this.peek() !== ',') throw this.error('an inline table needs , or }');
      this.pos += 1;
      this.skipBlank();
      if (this.peek() === '}') {
        this.pos += 1;
        return table;
      }
    }
  }

  private scalar(): TomlValue {
    const start = this.pos;
    while (!this.eof() && SCALAR.test(this.peek())) this.pos += 1;
    // A date and time may be separated by a space.
    if (/^\d{4}-\d{2}-\d{2}$/.test(this.src.slice(start, this.pos)) && /^ \d{2}:/.test(this.src.slice(this.pos, this.pos + 4))) {
      this.pos += 1;
      while (!this.eof() && SCALAR.test(this.peek())) this.pos += 1;
    }
    const token = this.src.slice(start, this.pos);
    if (token === 'true') return true;
    if (token === 'false') return false;
    const special = /^([+-]?)(inf|nan)$/.exec(token);
    if (special) return special[2] === 'nan' ? NaN : special[1] === '-' ? -Infinity : Infinity;
    const radix = /^0([xob])([0-9A-Fa-f_]+)$/.exec(token);
    if (radix) {
      const value = Number.parseInt(radix[2].replace(/_/g, ''), radix[1] === 'x' ? 16 : radix[1] === 'o' ? 8 : 2);
      if (Number.isNaN(value)) throw this.error(`invalid number ${token}`);
      return value;
    }
    if (/^[+-]?\d[\d_]*(\.\d[\d_]*)?([eE][+-]?\d[\d_]*)?$/.test(token)) return Number(token.replace(/_/g, ''));
    if (/^\d{4}-\d{2}-\d{2}/.test(token) || /^\d{2}:\d{2}/.test(token)) return token;
    throw this.error(token ? `invalid value ${token}` : 'a value is missing');
  }

  private basicString(): string {
    this.pos += 1;
    let out = '';
    for (;;) {
      if (this.eof()) throw this.error('a string is not closed');
      const c = this.next();
      if (c === '"') return out;
      if (c === '\n') throw this.error('a string is not closed on its line');
      out += c === '\\' ? this.escape() : c;
    }
  }

  private literalString(): string {
    this.pos += 1;
    const end = this.src.indexOf("'", this.pos);
    const newline = this.src.indexOf('\n', this.pos);
    if (end < 0 || (newline >= 0 && newline < end)) throw this.error('a string is not closed on its line');
    const out = this.src.slice(this.pos, end);
    this.pos = end + 1;
    return out;
  }

  /** `"""…"""` (escapes, line-ending backslashes) or `'''…'''` (as written). */
  private multilineString(delimiter: '"""' | "'''"): string {
    const basic = delimiter === '"""';
    const quote = delimiter[0];
    this.pos += 3;
    if (this.src.startsWith('\r\n', this.pos)) this.pos += 2;
    else if (this.peek() === '\n') this.pos += 1;
    let out = '';
    for (;;) {
      if (this.eof()) throw this.error('a multi-line string is not closed');
      if (this.src.startsWith(delimiter, this.pos)) {
        // Up to two quotes may sit just inside the closing delimiter.
        let run = 0;
        while (this.peek(run) === quote && run < 5) run += 1;
        out += quote.repeat(run - 3);
        this.pos += run;
        return out;
      }
      const c = this.next();
      if (basic && c === '\\') {
        const rest = /^[ \t]*\r?\n/.exec(this.src.slice(this.pos));
        if (rest) {
          this.pos += rest[0].length;
          while (!this.eof() && /[ \t\r\n]/.test(this.peek())) this.pos += 1;
        } else {
          out += this.escape();
        }
      } else {
        out += c;
      }
    }
  }

  private escape(): string {
    const c = this.next();
    if (c in ESCAPES) return ESCAPES[c];
    const width = c === 'u' ? 4 : c === 'U' ? 8 : c === 'x' ? 2 : 0;
    const hex = this.src.slice(this.pos, this.pos + width);
    if (width === 0 || !new RegExp(`^[0-9A-Fa-f]{${width}}$`).test(hex)) throw this.error(`invalid escape \\${c}`);
    this.pos += width;
    const code = Number.parseInt(hex, 16);
    if (code > 0x10ffff || (code >= 0xd800 && code <= 0xdfff)) throw this.error(`invalid escape \\${c}${hex}`);
    return String.fromCodePoint(code);
  }

  // ── Whitespace and lines ─────────────────────────────────────────────

  private skipSpaces(): void {
    while (this.peek() === ' ' || this.peek() === '\t') this.pos += 1;
  }

  /** Spaces, newlines and comments. */
  private skipBlank(): void {
    for (;;) {
      const c = this.peek();
      if (c === ' ' || c === '\t' || c === '\r' || c === '\n') this.pos += 1;
      else if (c === '#') this.skipComment();
      else return;
    }
  }

  private skipComment(): void {
    while (!this.eof() && this.peek() !== '\n') this.pos += 1;
  }

  private endOfLine(): void {
    this.skipSpaces();
    if (this.peek() === '#') this.skipComment();
    if (this.eof()) return;
    if (this.peek() === '\n') this.pos += 1;
    else if (this.src.startsWith('\r\n', this.pos)) this.pos += 2;
    else throw this.error('expected the end of the line');
  }

  private expect(text: string): void {
    this.skipSpaces();
    if (!this.src.startsWith(text, this.pos)) throw this.error(`expected ${text}`);
    this.pos += text.length;
  }

  private peek(offset = 0): string {
    return this.src.charAt(this.pos + offset);
  }

  private next(): string {
    const c = this.src.charAt(this.pos);
    this.pos += 1;
    return c;
  }

  private eof(): boolean {
    return this.pos >= this.src.length;
  }

  private error(message: string): Error {
    const line = this.src.slice(0, this.pos).split('\n').length;
    return new Error(`TOML line ${line}: ${message}`);
  }
}
