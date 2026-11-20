import type { Db } from '@eve/db';
import { integrationQueries, oauthAppConfigQueries, secretQueries } from '@eve/db';
import type { SecretStorageCounts } from '@eve/shared';

/** Stored credentials by format: what `eve system secrets reencrypt --dry-run` reports. */
export async function countStoredCredentials(db: Db): Promise<SecretStorageCounts> {
  const { v1 = 0, v2 = 0, ...others } = await secretQueries(db).countByFormat();
  return {
    secrets: { v1, v2, other: Object.values(others).reduce((sum, n) => sum + n, 0) },
    integration_tokens: await integrationQueries(db).countTokenFormats(),
    oauth_client_secrets: await oauthAppConfigQueries(db).countClientSecretFormats(),
    oauth_signing_secrets: await oauthAppConfigQueries(db).countSigningSecretFormats(),
  };
}

/** v1 secrets and plain OAuth columns: what re-encryption has still to take. */
export function legacyCredentialRows(counts: SecretStorageCounts): number {
  return counts.secrets.v1 + counts.integration_tokens.plain + counts.oauth_client_secrets.plain
    + counts.oauth_signing_secrets.plain;
}
