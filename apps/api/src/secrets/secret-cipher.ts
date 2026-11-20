import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes } from 'crypto';
import { BadRequestException, ForbiddenException, InternalServerErrorException } from '@nestjs/common';
import type { Db } from '@eve/db';
import { SEALED_ENVELOPE_PATTERN, systemSettingsQueries } from '@eve/db';
import { loadConfig } from '@eve/shared';
import type { SecurityService } from '../security/security.service.js';

/**
 * How Eve stores credentials at rest.
 *
 * - `v1:iv:tag:data`: AES-256-GCM under the master key, no associated data.
 * - `v2:iv:tag:data`: the same, with associated data naming where the value
 *   lives, so a ciphertext opens only in its own row: `scope_type|scope_id|key`
 *   for a secret, `table|id|field` for an integration token, an OAuth
 *   client secret or a Slack signing secret (stored plain before
 *   re-encryption).
 *
 * Every release from this one reads both. New writes stay `v1` (and plain
 * for the OAuth columns) until `eve system secrets reencrypt` sets the
 * instance setting `secrets.ciphertext_format` to `v2`, so a rollback to a
 * release that reads only `v1` stays possible until then.
 */
export const SECRETS_CIPHERTEXT_FORMAT_SETTING = 'secrets.ciphertext_format';

/** Instance rule: under `strict`, `v1` ciphertext and plain OAuth columns are refused. */
export const LEGACY_CIPHERTEXT_RULE = 'secrets.legacy_ciphertext';

export type CiphertextFormat = 'v1' | 'v2';

/** Where a secret lives; a `v2` ciphertext is bound to it. */
export interface SecretLocation {
  scope_type: string;
  scope_id: string;
  key: string;
}

/** A credential column outside the secrets table; its envelope is bound to the row and field. */
export interface ColumnLocation {
  table: 'integrations' | 'oauth_app_configs';
  id: string;
  /** `signing_secret` is `config_json.signing_secret` of an OAuth app config. */
  field: 'tokens_json' | 'client_secret' | 'signing_secret';
}

/** What a masked secret shows: a fixed mask, never a character of the value. */
export const SECRET_MASK = '••••••••';

const FORMAT_CACHE_MS = 30_000;
const ENVELOPE = new RegExp(SEALED_ENVELOPE_PATTERN);

export function secretAad(location: SecretLocation): string {
  return `${location.scope_type}|${location.scope_id}|${location.key}`;
}

export function columnAad(location: ColumnLocation): string {
  return `${location.table}|${location.id}|${location.field}`;
}

/** True when a stored column value is a `v2` envelope rather than plain text. */
export function isSealed(stored: string): boolean {
  return ENVELOPE.test(stored);
}

export function maskSecretValue(value: string): string {
  return value ? SECRET_MASK : '';
}

/** The AES key from the configured master key (as the first release derived it). */
export function deriveEncryptionKey(masterKey: string): Buffer {
  return createHash('sha256').update(masterKey).digest();
}

export function encryptPayload(key: Buffer, value: string, format: CiphertextFormat, aad: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  if (format === 'v2') cipher.setAAD(Buffer.from(aad, 'utf8'));
  const data = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${format}:${iv.toString('base64')}:${tag.toString('base64')}:${data.toString('base64')}`;
}

export function decryptPayload(key: Buffer, payload: string, aad: string): { value: string; format: CiphertextFormat } {
  const [version, ivB64, tagB64, dataB64, extra] = payload.split(':');
  if ((version !== 'v1' && version !== 'v2') || !ivB64 || !tagB64 || dataB64 === undefined || extra !== undefined) {
    throw new BadRequestException('Invalid secret payload');
  }
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivB64, 'base64'));
  if (version === 'v2') decipher.setAAD(Buffer.from(aad, 'utf8'));
  decipher.setAuthTag(Buffer.from(tagB64, 'base64'));
  const value = Buffer.concat([decipher.update(Buffer.from(dataB64, 'base64')), decipher.final()]).toString('utf8');
  return { value, format: version };
}

/**
 * Seals and opens stored credentials, decides the write format, and applies
 * `secrets.legacy_ciphertext`. One per service; the write format is cached
 * briefly, so a change reaches every replica within half a minute.
 */
export class SecretCipher {
  private keys: { encryption: Buffer; fingerprint: Buffer } | null | undefined;
  private formatCache: { value: CiphertextFormat; at: number } | null = null;

  /**
   * The master key is read from the config on first use (or given here),
   * so a service that never meets a sealed value needs no key.
   */
  constructor(
    private readonly db: Db | null,
    private readonly security?: SecurityService,
    private readonly masterKey?: string,
  ) {}

  get configured(): boolean {
    return this.loadKeys() !== null;
  }

  /**
   * The format new writes use: `v2` once the instance setting says so, or
   * when the instance enforces `secrets.legacy_ciphertext` (it could not
   * read a `v1` write back); `v1` otherwise.
   */
  async writeFormat(): Promise<CiphertextFormat> {
    if (this.formatCache && Date.now() - this.formatCache.at < FORMAT_CACHE_MS) return this.formatCache.value;
    const setting = this.db ? (await systemSettingsQueries(this.db).get(SECRETS_CIPHERTEXT_FORMAT_SETTING))?.value : null;
    let value: CiphertextFormat = setting === 'v2' ? 'v2' : 'v1';
    if (value === 'v1' && this.security
      && (await this.security.effectiveProfile({}, 'instance', LEGACY_CIPHERTEXT_RULE)) === 'strict') {
      value = 'v2';
    }
    this.formatCache = { value, at: Date.now() };
    return value;
  }

  /** Forget the cached write format (after this process changed the setting). */
  forgetWriteFormat(): void {
    this.formatCache = null;
  }

  async sealSecret(location: SecretLocation, value: string, format?: CiphertextFormat): Promise<string> {
    return encryptPayload(this.requireKey(), value, format ?? (await this.writeFormat()), secretAad(location));
  }

  async openSecret(location: SecretLocation, payload: string): Promise<string> {
    const key = this.requireKey();
    if (payload.startsWith('v1:')) {
      await this.legacyRead({ store: 'secrets', scope_type: location.scope_type, key: location.key });
    }
    return decryptPayload(key, payload, secretAad(location)).value;
  }

  /**
   * A stored secret re-sealed as `v2` at its location, whatever its format:
   * for re-encryption, which runs whatever the profile says about `v1`.
   */
  resealSecret(location: SecretLocation, payload: string): string {
    const key = this.requireKey();
    const aad = secretAad(location);
    return encryptPayload(key, decryptPayload(key, payload, aad).value, 'v2', aad);
  }

  /** A column value as stored: plain under `v1`, an envelope under `v2`. */
  async sealColumn(location: ColumnLocation, value: string, format?: CiphertextFormat): Promise<string> {
    if ((format ?? (await this.writeFormat())) === 'v1') return value;
    return encryptPayload(this.requireKey(), value, 'v2', columnAad(location));
  }

  async openColumn(location: ColumnLocation, stored: string): Promise<string> {
    if (!isSealed(stored)) {
      await this.legacyRead({ store: location.table, field: location.field });
      return stored;
    }
    return decryptPayload(this.requireKey(), stored, columnAad(location)).value;
  }

  /** Integration tokens as stored: the object under `v1`, an envelope (a JSON string) under `v2`. */
  async sealTokens(
    integrationId: string,
    tokens: Record<string, unknown> | null,
    format?: CiphertextFormat,
  ): Promise<Record<string, unknown> | string | null> {
    if (tokens === null) return null;
    if ((format ?? (await this.writeFormat())) === 'v1') return tokens;
    return this.sealColumn({ table: 'integrations', id: integrationId, field: 'tokens_json' }, JSON.stringify(tokens), 'v2');
  }

  async openTokens(integrationId: string, stored: unknown): Promise<Record<string, unknown> | null> {
    if (stored === null || stored === undefined) return null;
    if (typeof stored !== 'string') {
      await this.legacyRead({ store: 'integrations', field: 'tokens_json' });
      return stored as Record<string, unknown>;
    }
    if (!isSealed(stored)) throw new BadRequestException('Invalid integration token payload');
    const opened = await this.openColumn({ table: 'integrations', id: integrationId, field: 'tokens_json' }, stored);
    return JSON.parse(opened) as Record<string, unknown>;
  }

  /**
   * A value's fingerprint, to tell whether two values match without showing
   * either: 12 hex of an HMAC over the scope, key and value, under a key
   * derived from the master key. The fields are JSON-encoded, so none can
   * run into the next.
   */
  fingerprint(location: SecretLocation, value: string): string {
    const keys = this.loadKeys();
    if (!keys) throw new InternalServerErrorException('Secrets master key not configured');
    return createHmac('sha256', keys.fingerprint)
      .update(JSON.stringify([location.scope_type, location.scope_id, location.key, value]))
      .digest('hex')
      .slice(0, 12);
  }

  private requireKey(): Buffer {
    const keys = this.loadKeys();
    if (!keys) throw new InternalServerErrorException('Secrets master key not configured');
    return keys.encryption;
  }

  private loadKeys(): { encryption: Buffer; fingerprint: Buffer } | null {
    if (this.keys === undefined) {
      const masterKey = this.masterKey ?? loadConfig().EVE_SECRETS_MASTER_KEY;
      const encryption = masterKey ? deriveEncryptionKey(masterKey) : null;
      this.keys = encryption
        ? {
            encryption,
            fingerprint: Buffer.from(hkdfSync('sha256', encryption, Buffer.alloc(0), 'eve-secret-mask-fingerprint', 32)),
          }
        : null;
    }
    return this.keys;
  }

  /** A read in a legacy format: recorded under `audit`, refused under `strict`. */
  private async legacyRead(detail: Record<string, string>): Promise<void> {
    if (!this.security) return;
    const profile = await this.security.decide(LEGACY_CIPHERTEXT_RULE, { governing: 'instance', detail });
    if (profile === 'strict') {
      throw new ForbiddenException(
        `A credential stored in a legacy format is refused; run eve system secrets reencrypt (rule ${LEGACY_CIPHERTEXT_RULE})`,
      );
    }
  }
}
