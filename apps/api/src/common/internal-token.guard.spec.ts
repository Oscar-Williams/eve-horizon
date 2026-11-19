import { createHash } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ForbiddenException, UnauthorizedException, type ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { SecurityProfile } from '@eve/shared';
import { InternalCallers, InternalTokenGuard } from './internal-token.guard.js';
import { workerRequestHeaders } from './worker-url.js';

const CORE = 'core-key-0123456789';
const GATEWAY = 'gateway-key-0123456789';
const SSO = 'sso-key-0123456789';
const LEGACY = 'internal-key';
const sha = (value: string) => createHash('sha256').update(value, 'utf8').digest('hex');

/** Stand-ins for three controllers: secrets resolve (core only), a gateway controller, an SSO route. */
class SecretsInternalController {
  resolve() {}
}
@InternalCallers('gateway')
class IntegrationsInternalController {
  resolveIntegration() {}
}
class AuthInternalController {
  @InternalCallers('sso')
  consumeMagicLinkWrap() {}
  mintServiceToken() {}
}

function contextFor(
  headers: Record<string, string | string[] | undefined>,
  cls: new () => object,
  handler: string,
): ExecutionContext {
  return {
    switchToHttp: () => ({ getRequest: () => ({ headers }) }),
    getClass: () => cls,
    getHandler: () => (cls.prototype as Record<string, unknown>)[handler],
  } as unknown as ExecutionContext;
}

/** SecurityService's decide and gate, under one instance profile, recording each finding. */
function fakeSecurity(profile: SecurityProfile) {
  const findings: Array<{ rule: string; ctx: Record<string, unknown> }> = [];
  const decide = vi.fn(async (rule: string, ctx: Record<string, unknown>) => {
    if (profile !== 'legacy') findings.push({ rule, ctx });
    return profile;
  });
  const gate = vi.fn(async (rule: string, ctx: Record<string, unknown>) => {
    const p = await decide(rule, ctx);
    if (p === 'strict') throw new ForbiddenException(`Refused (rule ${rule})`);
    return p === 'legacy' ? 'allowed' : 'recorded';
  });
  return { decide, gate, findings };
}

function guardUnder(profile: SecurityProfile) {
  const security = fakeSecurity(profile);
  return { guard: new InternalTokenGuard(new Reflector(), security as never), security };
}

const core = { 'x-eve-service-key': `core.${CORE}` };
const gateway = { 'x-eve-service-key': `gateway.${GATEWAY}` };
const sso = { 'x-eve-service-key': `sso.${SSO}` };
const legacy = { 'x-eve-internal-token': LEGACY };

describe('InternalTokenGuard', () => {
  beforeEach(() => {
    // loadConfig() validates the whole environment.
    vi.stubEnv('DATABASE_URL', 'postgres://user:pass@localhost:5432/eve_test');
    vi.stubEnv('EVE_INTERNAL_API_KEY', LEGACY);
    vi.stubEnv('EVE_INTERNAL_CORE_KEY', CORE);
    vi.stubEnv('EVE_INTERNAL_CALLER_HASHES', `gateway:${sha(GATEWAY)},sso:${sha(SSO)}`);
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('accepts the core key on every internal route, with no finding, under strict', async () => {
    const { guard, security } = guardUnder('strict');
    await expect(guard.canActivate(contextFor(core, SecretsInternalController, 'resolve'))).resolves.toBe(true);
    await expect(guard.canActivate(contextFor(core, IntegrationsInternalController, 'resolveIntegration'))).resolves.toBe(true);
    await expect(guard.canActivate(contextFor(core, AuthInternalController, 'mintServiceToken'))).resolves.toBe(true);
    expect(security.findings).toEqual([]);
  });

  it('accepts the gateway and SSO keys on their own routes under strict', async () => {
    const { guard, security } = guardUnder('strict');
    await expect(guard.canActivate(contextFor(gateway, IntegrationsInternalController, 'resolveIntegration'))).resolves.toBe(true);
    await expect(guard.canActivate(contextFor(sso, AuthInternalController, 'consumeMagicLinkWrap'))).resolves.toBe(true);
    expect(security.findings).toEqual([]);
  });

  it('under strict, the gateway key gets 403 on secrets resolve and the SSO key 403 off its routes', async () => {
    const { guard, security } = guardUnder('strict');
    await expect(guard.canActivate(contextFor(gateway, SecretsInternalController, 'resolve'))).rejects.toThrow(ForbiddenException);
    await expect(guard.canActivate(contextFor(sso, AuthInternalController, 'mintServiceToken'))).rejects.toThrow(ForbiddenException);
    await expect(guard.canActivate(contextFor(sso, IntegrationsInternalController, 'resolveIntegration'))).rejects.toThrow(ForbiddenException);
    expect(security.findings.map((f) => f.rule)).toEqual(['internal.service_key', 'internal.service_key', 'internal.service_key']);
    expect(security.findings[0].ctx).toMatchObject({
      governing: 'instance',
      principal: { type: 'service', id: 'gateway' },
      detail: { caller: 'gateway', route: 'SecretsInternalController.resolve' },
    });
  });

  it('under strict, a call with only the legacy key gets 401', async () => {
    const { guard, security } = guardUnder('strict');
    await expect(guard.canActivate(contextFor(legacy, SecretsInternalController, 'resolve'))).rejects.toThrow(UnauthorizedException);
    expect(security.findings).toHaveLength(1);
    expect(security.findings[0]).toMatchObject({
      rule: 'internal.service_key',
      ctx: { governing: 'instance', principal: { type: 'service', id: 'legacy-key' } },
    });
  });

  it('under audit, the gateway off its routes and a legacy-only call both pass and are recorded', async () => {
    const { guard, security } = guardUnder('audit');
    await expect(guard.canActivate(contextFor(gateway, SecretsInternalController, 'resolve'))).resolves.toBe(true);
    await expect(guard.canActivate(contextFor(legacy, SecretsInternalController, 'resolve'))).resolves.toBe(true);
    expect(security.findings.map((f) => (f.ctx.principal as { id: string }).id)).toEqual(['gateway', 'legacy-key']);
  });

  it('under legacy, both pass and nothing is recorded', async () => {
    const { guard, security } = guardUnder('legacy');
    await expect(guard.canActivate(contextFor(gateway, SecretsInternalController, 'resolve'))).resolves.toBe(true);
    await expect(guard.canActivate(contextFor(legacy, SecretsInternalController, 'resolve'))).resolves.toBe(true);
    expect(security.findings).toEqual([]);
  });

  it('judges a call with both headers on the service key', async () => {
    const { guard } = guardUnder('strict');
    await expect(
      guard.canActivate(contextFor({ ...gateway, ...legacy }, SecretsInternalController, 'resolve')),
    ).rejects.toThrow(ForbiddenException);
    await expect(
      guard.canActivate(contextFor({ ...core, ...legacy }, SecretsInternalController, 'resolve')),
    ).resolves.toBe(true);
  });

  it('rejects a missing or wrong key, and a wrong service key with no legacy key', async () => {
    const { guard } = guardUnder('legacy');
    await expect(guard.canActivate(contextFor({}, SecretsInternalController, 'resolve'))).rejects.toThrow(UnauthorizedException);
    await expect(
      guard.canActivate(contextFor({ 'x-eve-internal-token': 'internal-kez' }, SecretsInternalController, 'resolve')),
    ).rejects.toThrow(UnauthorizedException);
    await expect(
      guard.canActivate(contextFor({ 'x-eve-internal-token': [LEGACY] }, SecretsInternalController, 'resolve')),
    ).rejects.toThrow(UnauthorizedException);
    await expect(
      guard.canActivate(contextFor({ 'x-eve-service-key': `core.${GATEWAY}` }, SecretsInternalController, 'resolve')),
    ).rejects.toThrow(UnauthorizedException);
  });

  it('fails closed when no key is configured', async () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', '');
    vi.stubEnv('EVE_INTERNAL_CORE_KEY', '');
    vi.stubEnv('EVE_INTERNAL_CALLER_HASHES', '');
    const { guard } = guardUnder('legacy');
    await expect(
      guard.canActivate(contextFor({ 'x-eve-internal-token': '', 'x-eve-service-key': 'core.' }, SecretsInternalController, 'resolve')),
    ).rejects.toThrow(UnauthorizedException);
  });
});

describe('workerRequestHeaders', () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('authenticates API-to-worker calls with the core key, and the legacy key while it is set', () => {
    vi.stubEnv('EVE_INTERNAL_API_KEY', LEGACY);
    vi.stubEnv('EVE_INTERNAL_CORE_KEY', CORE);
    expect(workerRequestHeaders()).toEqual({
      'content-type': 'application/json',
      'x-eve-service-key': `core.${CORE}`,
      'x-eve-internal-token': LEGACY,
    });
  });
});
