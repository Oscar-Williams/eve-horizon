import { createHmac } from 'node:crypto';
import { UnauthorizedException } from '@nestjs/common';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { SecurityProfile } from '@eve/shared';
import { GitHubController } from './github.controller.js';

/**
 * webhooks.global_secret: a project with no GITHUB_WEBHOOK_SECRET of its own
 * falls back to the instance's EVE_GITHUB_WEBHOOK_SECRET under `legacy` and
 * `audit` (recorded), and gets 401 under `strict`.
 */
const PROJECT = 'proj_shop';
const GLOBAL = 'global-webhook-secret';
const OWN = 'project-webhook-secret';
const payload = { ref: 'refs/heads/main', after: 'abc123', sender: { login: 'alice' } };
const rawBody = JSON.stringify(payload);
const sign = (secret: string) => `sha256=${createHmac('sha256', secret).update(rawBody).digest('hex')}`;

describe('GitHub webhooks and the global secret', () => {
  let projectSecret: string | null;
  let profile: SecurityProfile;
  const findings: Array<{ rule: string; ctx: Record<string, unknown> }> = [];
  const create = vi.fn(async () => ({ id: 'evt_1' }));
  let controller: GitHubController;

  beforeEach(() => {
    vi.stubEnv('DATABASE_URL', 'postgres://user:pass@localhost:5432/eve_test');
    vi.stubEnv('EVE_GITHUB_WEBHOOK_SECRET', GLOBAL);
    projectSecret = null;
    profile = 'legacy';
    findings.length = 0;
    create.mockClear();
    const security = {
      decide: vi.fn(async (rule: string, ctx: Record<string, unknown>) => {
        if (profile !== 'legacy') findings.push({ rule, ctx });
        return profile;
      }),
    };
    controller = new GitHubController(
      { create } as never,
      { resolveProjectSecretValue: vi.fn(async () => projectSecret) } as never,
      security as never,
    );
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  const deliver = (signature: string) =>
    controller.handleWebhook(PROJECT, 'push', signature, 'delivery-1', payload as never, { rawBody });

  it('accepts a project\'s own secret under strict, with no finding', async () => {
    projectSecret = OWN;
    profile = 'strict';
    await expect(deliver(sign(OWN))).resolves.toMatchObject({ ok: true });
    expect(findings).toEqual([]);
  });

  it('under legacy, falls back to the global secret and records nothing', async () => {
    await expect(deliver(sign(GLOBAL))).resolves.toMatchObject({ ok: true });
    expect(findings).toEqual([]);
  });

  it('under audit, falls back to the global secret and records it', async () => {
    profile = 'audit';
    await expect(deliver(sign(GLOBAL))).resolves.toMatchObject({ ok: true });
    expect(findings).toEqual([
      expect.objectContaining({
        rule: 'webhooks.global_secret',
        ctx: expect.objectContaining({ governing: 'project', projectId: PROJECT }),
      }),
    ]);
  });

  it('under strict, a project with no secret of its own gets 401', async () => {
    profile = 'strict';
    await expect(deliver(sign(GLOBAL))).rejects.toThrow(UnauthorizedException);
    expect(create).not.toHaveBeenCalled();
    expect(findings.map((f) => f.rule)).toEqual(['webhooks.global_secret']);
  });

  it('records nothing for a delivery whose signature does not verify', async () => {
    profile = 'audit';
    await expect(deliver(sign('wrong-secret'))).rejects.toThrow(UnauthorizedException);
    expect(findings).toEqual([]);
  });
});
