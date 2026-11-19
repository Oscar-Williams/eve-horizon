import { describe, expect, it } from 'vitest';
import { ManifestSchema } from '../manifest.js';

// x-eve.security: the numeric user a service runs as under the strict pod
// security profile, and its two opt-outs.

function parse(security: unknown) {
  return ManifestSchema.safeParse({
    services: { web: { image: 'web:1', 'x-eve': { security } } },
  });
}

describe('manifest x-eve.security', () => {
  it('accepts a numeric user and group, run_as_root and allowed capabilities', () => {
    const result = parse({
      run_as_user: 1000,
      run_as_group: 1000,
      run_as_root: false,
      capabilities: ['NET_BIND_SERVICE', 'CHOWN', 'SETUID', 'SETGID', 'DAC_OVERRIDE'],
    });

    expect(result.success).toBe(true);
    const security = (result as any).data.services.web['x-eve'].security;
    expect(security).toEqual({
      run_as_user: 1000,
      run_as_group: 1000,
      run_as_root: false,
      capabilities: ['NET_BIND_SERVICE', 'CHOWN', 'SETUID', 'SETGID', 'DAC_OVERRIDE'],
    });
  });

  it('refuses a user name, a negative uid and a capability outside the allow list', () => {
    expect(parse({ run_as_user: 'node' }).success).toBe(false);
    expect(parse({ run_as_user: -1 }).success).toBe(false);
    expect(parse({ run_as_group: 1.5 }).success).toBe(false);
    expect(parse({ capabilities: ['SYS_ADMIN'] }).success).toBe(false);
    expect(parse({ capabilities: ['NET_RAW'] }).success).toBe(false);
  });

  it('refuses an unknown field, so a misspelt opt-out is not silently ignored', () => {
    expect(parse({ run_as_usr: 1000 }).success).toBe(false);
  });
});
