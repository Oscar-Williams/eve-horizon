import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { INTERNAL_CALLERS_KEY } from './internal-token.guard.js';
import { AgentRuntimeInternalController } from '../agent-runtime/agent-runtime.internal.controller.js';
import { AttemptsInternalController } from '../attempts/attempts.internal.controller.js';
import { AuthInternalController } from '../auth/auth.internal.controller.js';
import { ChatGatewayController } from '../chat/chat.gateway.controller.js';
import { ChatInternalController } from '../chat/chat.internal.controller.js';
import { EventsInternalController } from '../events/events.internal.controller.js';
import { IntegrationsInternalController } from '../integrations/integrations.internal.controller.js';
import { OrgsInternalController } from '../orgs/orgs.internal.controller.js';
import { PipelineExpanderInternalController } from '../pipelines/pipeline-expander.internal.controller.js';
import { PipelineRunsInternalController } from '../pipelines/pipeline-runs.internal.controller.js';
import { PlatformNotifyController } from '../platform-notify/platform-notify.controller.js';
import { RegistryTokenController } from '../registry/registry-token.controller.js';
import { SecretsInternalController, SecretsWriteBackController } from '../secrets/secrets.internal.controller.js';
import { SecurityInternalController } from '../security/security.internal.controller.js';
import { StorageInternalController } from '../storage/storage.internal.controller.js';
import { WorkflowsInternalController } from '../workflows/workflows.internal.controller.js';

/**
 * Each internal route the gateway or the SSO calls declares it with
 * @InternalCallers, so their keys work there under `strict` and nowhere else.
 * The routes are read from the gateway's and the SSO's own source.
 */
const controllers: Array<new (...args: never[]) => object> = [
  AgentRuntimeInternalController,
  AttemptsInternalController,
  AuthInternalController,
  ChatGatewayController,
  ChatInternalController,
  EventsInternalController,
  IntegrationsInternalController,
  OrgsInternalController,
  PipelineExpanderInternalController,
  PipelineRunsInternalController,
  PlatformNotifyController,
  RegistryTokenController,
  SecretsInternalController,
  SecretsWriteBackController,
  SecurityInternalController,
  StorageInternalController,
  WorkflowsInternalController,
];

interface Route {
  pattern: string[];
  name: string;
  callers: string[];
}

function segments(path: string): string[] {
  return path.split('/').filter(Boolean);
}

const routes: Route[] = controllers.flatMap((cls) => {
  const base = String(Reflect.getMetadata('path', cls) ?? '');
  const classCallers: string[] = Reflect.getMetadata(INTERNAL_CALLERS_KEY, cls) ?? [];
  return Object.getOwnPropertyNames(cls.prototype)
    .filter((name) => name !== 'constructor')
    .flatMap((name) => {
      const handler = (cls.prototype as Record<string, unknown>)[name];
      if (typeof handler !== 'function' || Reflect.getMetadata('method', handler) === undefined) return [];
      const path = String(Reflect.getMetadata('path', handler) ?? '');
      const handlerCallers: string[] | undefined = Reflect.getMetadata(INTERNAL_CALLERS_KEY, handler);
      return [{
        pattern: segments(`${base}/${path}`),
        name: `${cls.name}.${name}`,
        callers: handlerCallers ?? classCallers,
      }];
    });
});

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return /\.ts$/.test(entry) && !/\.(spec|test)\.ts$/.test(entry) ? [full] : [];
  });
}

/** Every `/internal/...` path literal in an app's source, with `${...}` as one segment. */
function internalPathsCalledBy(app: string): string[] {
  const root = join(__dirname, '..', '..', '..', app, 'src');
  const paths = new Set<string>();
  for (const file of sourceFiles(root)) {
    const text = readFileSync(file, 'utf8');
    for (const match of text.matchAll(/['`](\/internal\/[^'`\s]+)['`]/g)) {
      paths.add(match[1].replace(/\$\{[^}]+\}/g, ':value'));
    }
  }
  return [...paths];
}

function routesFor(path: string): Route[] {
  const wanted = segments(path);
  return routes.filter((route) =>
    route.pattern.length === wanted.length &&
    route.pattern.every((segment, i) => segment.startsWith(':') || wanted[i].startsWith(':') || segment === wanted[i]));
}

describe('@InternalCallers on the routes the gateway and the SSO call', () => {
  it.each([
    ['gateway', 11],
    ['sso', 2],
  ])('every API route the %s calls declares it', (caller, atLeast) => {
    const called = internalPathsCalledBy(caller).filter((path) => routesFor(path).length > 0);
    expect(called.length).toBeGreaterThanOrEqual(atLeast);
    const undeclared = called.filter((path) => !routesFor(path).some((route) => route.callers.includes(caller)));
    expect(undeclared).toEqual([]);
  });

  it('no other route accepts the gateway or SSO keys', () => {
    const gatewayRoutes = new Set(internalPathsCalledBy('gateway').flatMap((path) => routesFor(path).map((r) => r.name)));
    const ssoRoutes = new Set(internalPathsCalledBy('sso').flatMap((path) => routesFor(path).map((r) => r.name)));
    const extra = routes.filter((route) =>
      (route.callers.includes('gateway') && !gatewayRoutes.has(route.name)) ||
      (route.callers.includes('sso') && !ssoRoutes.has(route.name)));
    expect(extra.map((r) => r.name)).toEqual([]);
  });

  it('keeps magic-link-wrap SSO only, integrations/active gateway only, and secrets resolve core only', () => {
    const named = (name: string) => routes.find((r) => r.name === name)?.callers;
    expect(named('AuthInternalController.consumeMagicLinkWrap')).toEqual(['sso']);
    expect(named('AuthInternalController.inspectMagicLinkWrap')).toEqual(['sso']);
    expect(named('AuthInternalController.mintServiceToken')).toEqual([]);
    expect(named('IntegrationsInternalController.listActiveIntegrations')).toEqual(['gateway']);
    expect(routes.filter((r) => r.name.startsWith('SecretsInternalController.')).every((r) => r.callers.length === 0)).toBe(true);
  });
});
