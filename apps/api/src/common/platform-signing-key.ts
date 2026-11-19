import { hkdfSync } from 'node:crypto';

/**
 * Keys for tokens the API signs for itself and verifies itself (identity
 * link tokens, Slack install links, org filesystem link tokens without
 * their own secret).
 *
 * New tokens are signed with a key derived, per purpose, from the core key
 * (`EVE_INTERNAL_CORE_KEY`), so the legacy `EVE_INTERNAL_API_KEY` can be
 * removed. Until a core key is set they are signed with the legacy key.
 * While the legacy key is set, tokens it signed still verify.
 */
export function platformSigningKeys(
  purpose: string,
  env: Record<string, string | undefined> = process.env,
): { sign: string | undefined; verify: string[] } {
  const derived = env.EVE_INTERNAL_CORE_KEY
    ? Buffer.from(hkdfSync('sha256', env.EVE_INTERNAL_CORE_KEY, Buffer.alloc(0), `eve-platform-signing/${purpose}`, 32))
      .toString('base64url')
    : undefined;
  const legacy = env.EVE_INTERNAL_API_KEY || undefined;
  const verify = [derived, legacy].filter((key): key is string => Boolean(key));
  return { sign: derived ?? legacy, verify };
}
