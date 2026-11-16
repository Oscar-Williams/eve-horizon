import { describe, expect, it } from 'vitest';
import { formatAppLinkTokens } from '../src/commands/job';

const TOKENS = [
  { alias: 'opps', name: 'opps', env_var: 'EVE_APP_LINK_OPPS_TOKEN', access_token: 'tok-opps', expires_at: 1_900_000_000 },
  { alias: 'billing', name: 'billing', env_var: 'EVE_APP_LINK_BILLING_TOKEN', access_token: 'tok-billing', expires_at: 1_900_000_000 },
];

describe('eve job app-link-token output', () => {
  it('prints just the token for one link, ready for $(...)', () => {
    expect(formatAppLinkTokens([TOKENS[0]], { env: false })).toBe('tok-opps');
  });

  it('prints export lines with --env, ready for eval', () => {
    expect(formatAppLinkTokens(TOKENS, { env: true })).toBe(
      "export EVE_APP_LINK_OPPS_TOKEN='tok-opps'\nexport EVE_APP_LINK_BILLING_TOKEN='tok-billing'",
    );
  });

  it('prints NAME=token lines for several links without --env', () => {
    expect(formatAppLinkTokens(TOKENS, { env: false })).toBe(
      'EVE_APP_LINK_OPPS_TOKEN=tok-opps\nEVE_APP_LINK_BILLING_TOKEN=tok-billing',
    );
  });
});
