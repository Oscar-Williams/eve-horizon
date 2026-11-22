import { afterEach, describe, expect, it, vi } from 'vitest';
import { handleDoctor, handleSystemSecurity } from '../src/commands/security';

vi.mock('../src/lib/client', () => ({
  requestJson: vi.fn(),
}));

import { requestJson } from '../src/lib/client';

/**
 * `legacy` is deprecated in 0.1.330 and removed in 0.1.331: setting it
 * prints the API's warning, and `eve doctor security` lists every level that
 * resolves to it.
 */

const context = { apiUrl: 'http://eve.example', token: 'token', profile: null, profileName: null };
const WARNING = 'legacy is deprecated and is removed in 0.1.331; use audit';

const report = {
  days: 14,
  current_ruleset: 4,
  instance_profile: 'legacy',
  instance_ruleset: null,
  new_project_profile: null,
  orgs: [{ id: 'org_acme', slug: 'acme', profile: 'legacy', effective: 'legacy' }],
  projects: [{ id: 'proj_shop', slug: 'shop', org_id: 'org_acme', profile: null, effective: 'legacy' }],
  summary: [],
  findings: [],
};

function output(log: ReturnType<typeof vi.spyOn>): string {
  return log.mock.calls.map((call) => String(call[0])).join('\n');
}

describe('legacy deprecation in the CLI', () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.mocked(requestJson).mockReset();
  });

  it('prints the warning when a profile is set to legacy', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce({
      scope: 'project', id: 'proj_shop', profile: 'legacy', ruleset: null, warnings: [WARNING],
    });
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);

    await handleSystemSecurity(['profile', 'legacy'], { project: 'proj_shop' }, context as never, false);

    expect(output(log)).toContain(`Warning: ${WARNING}`);
  });

  it('prints no warning for audit', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce({ scope: 'instance', id: null, profile: 'audit', ruleset: null });
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);

    await handleSystemSecurity(['profile', 'audit'], {}, context as never, false);

    expect(output(log)).not.toContain('Warning:');
  });

  it('lists the levels that resolve to legacy in eve doctor security', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce({
      ...report,
      legacy_levels: [
        { scope: 'instance', id: null, slug: null, source: 'unset' },
        { scope: 'org', id: 'org_acme', slug: 'acme', source: 'set' },
        { scope: 'project', id: 'proj_shop', slug: 'shop', source: 'inherited' },
      ],
      warnings: [WARNING],
    });
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);

    await handleDoctor('security', {}, context as never);

    const text = output(log);
    expect(text).toContain(`Warning: ${WARNING}`);
    expect(text).toContain('Levels on legacy:');
    expect(text).toContain('  instance: no profile set, which means legacy');
    expect(text).toContain('  org acme (org_acme): set to legacy');
    expect(text).toContain('  project shop (proj_shop): inherits legacy');
  });

  it('prints no legacy section when no level is on legacy', async () => {
    vi.mocked(requestJson).mockResolvedValueOnce({
      ...report,
      instance_profile: 'audit',
      orgs: [{ ...report.orgs[0], profile: null, effective: 'audit' }],
      projects: [{ ...report.projects[0], effective: 'audit' }],
      legacy_levels: [],
      warnings: [],
    });
    const log = vi.spyOn(console, 'log').mockImplementation(() => undefined);

    await handleDoctor('security', {}, context as never);

    expect(output(log)).not.toContain('legacy');
  });
});
