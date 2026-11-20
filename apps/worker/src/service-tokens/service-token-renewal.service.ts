import { createPublicKey, verify as verifySignature, type JsonWebKey, type KeyObject } from 'node:crypto';
import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { environmentQueries, type Db, type ServiceTokenRenewalTarget } from '@eve/db';
import { fetchSigningKey, mintAppLinkToken, mintServiceToken, toK8sLabelValue } from '@eve/shared';
import { K8sService } from '../deployer/k8s.service';
import {
  SECRETS_HASH_ANNOTATION,
  SECRET_DEPLOYMENT_ANNOTATION,
  SERVICE_SECRETS_LABEL,
  secretsHash,
} from '../deployer/workload-secrets';

const HOUR_MS = 60 * 60 * 1000;
/** The first run waits a minute after start, so the API is up after a platform upgrade. */
const FIRST_RUN_DELAY_MS = 60 * 1000;
const DAY_SECONDS = 24 * 60 * 60;
/** Service and injected app-link tokens live 90 days, the most the API mints. */
const TOKEN_TTL_SECONDS = 90 * DAY_SECONDS;
const DEFAULT_RENEW_DAYS = 30;
/** A longer window would renew a fresh 90-day token again within the month. */
const MAX_RENEW_DAYS = 60;
const APP_LINK_TOKEN_KEY = /^EVE_APP_LINK_[A-Z0-9_]+_TOKEN$/;

export const SERVICE_TOKEN_ISSUER = 'SERVICE_TOKEN_ISSUER';

export type RenewalReason = 'expiring' | 'retired_key' | 'revoked';

export interface RenewedToken {
  env_id: string;
  namespace: string;
  secret: string;
  key: string;
  reason: RenewalReason;
}

interface SigningKey {
  kid: string;
  publicKey: KeyObject;
}

/** What renewal asks the API for: the key it signs with now, and fresh tokens. */
export interface ServiceTokenIssuer {
  signingKey(): Promise<SigningKey | null>;
  mintServiceToken(params: {
    projectId: string;
    orgId: string;
    envName: string;
    serviceName: string;
    permissions: string[];
    releaseId: string;
  }): Promise<string | null>;
  mintAppLinkToken(params: {
    subscriptionId: string;
    consumerPrincipal: string;
    consumerProjectId: string;
    consumerEnv: string;
    producerEnv: string;
    ttlSeconds: number;
  }): Promise<string | null>;
}

/** The internal API: the deployer's own mint calls, and the signing-key route. */
@Injectable()
export class ApiServiceTokenIssuer implements ServiceTokenIssuer {
  async signingKey(): Promise<SigningKey | null> {
    const key = await fetchSigningKey();
    if (!key) return null;
    try {
      return { kid: key.kid, publicKey: createPublicKey({ key: key.public_key as JsonWebKey, format: 'jwk' }) };
    } catch {
      return null;
    }
  }

  async mintServiceToken(params: Parameters<ServiceTokenIssuer['mintServiceToken']>[0]): Promise<string | null> {
    return (await mintServiceToken({ ...params, ttlSeconds: TOKEN_TTL_SECONDS }))?.access_token ?? null;
  }

  async mintAppLinkToken(params: Parameters<ServiceTokenIssuer['mintAppLinkToken']>[0]): Promise<string | null> {
    return (await mintAppLinkToken(params))?.access_token ?? null;
  }
}

interface DecodedToken {
  kid?: string;
  claims: Record<string, unknown>;
  signingInput: string;
  signature: Buffer;
  iat: number;
  exp: number;
}

interface RenewalPolicy {
  /** Now, in seconds. */
  now: number;
  /** Renew a token with this long left or less; 0 for none on expiry alone. */
  renewWithinSeconds: number;
  /** The key the API signs with now; null when it could not be read. */
  signingKey: SigningKey | null;
  /** The environment's service_tokens_not_before, in seconds. */
  notBefore: number | null;
}

/** A token Eve minted for the service whose Secret holds it, and how to mint it again. */
type HeldToken =
  | { kind: 'service'; token: DecodedToken; serviceName: string; permissions: string[] }
  | {
      kind: 'app_link';
      token: DecodedToken;
      subscriptionId: string;
      principal: string;
      producerEnv: string;
    };

function decodeToken(raw: string): DecodedToken | null {
  const parts = raw.split('.');
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8')) as Record<string, unknown> | null;
    const claims = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8')) as Record<string, unknown> | null;
    if (!claims || typeof claims !== 'object' || typeof claims.iat !== 'number' || typeof claims.exp !== 'number') {
      return null;
    }
    return {
      kid: typeof header?.kid === 'string' ? header.kid : undefined,
      claims,
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: Buffer.from(parts[2], 'base64url'),
      iat: claims.iat,
      exp: claims.exp,
    };
  } catch {
    return null;
  }
}

function signedWith(token: DecodedToken, key: SigningKey): boolean {
  if (token.kid !== key.kid) return false;
  try {
    return verifySignature('RSA-SHA256', Buffer.from(token.signingInput), key.publicKey, token.signature);
  } catch {
    return false;
  }
}

/** Why a token is renewed now, or null to leave it. */
export function renewalReason(token: DecodedToken, policy: RenewalPolicy): RenewalReason | null {
  if (policy.renewWithinSeconds > 0 && token.exp - policy.now <= policy.renewWithinSeconds) return 'expiring';
  if (policy.signingKey && !signedWith(token, policy.signingKey)) return 'retired_key';
  if (policy.notBefore !== null && token.iat < policy.notBefore) return 'revoked';
  return null;
}

const iso = (seconds: number) => new Date(seconds * 1000).toISOString();

/**
 * Renews the Eve tokens of deployed services before they lapse (EVE-057).
 * Hourly, for each deployed environment, it reads the service Secrets the
 * applied release wrote and renews a service token, or an app-link token
 * injected into the service, that expires within EVE_SERVICE_TOKEN_RENEW_DAYS
 * (default 30; 0 turns the hourly renewal off), was not signed by the API's
 * current key, or was issued before the environment's
 * service_tokens_not_before. The new token has the same permissions, held to
 * the release's manifest by the API.
 *
 * It writes only the renewed keys, on the Secret's resourceVersion (a deploy
 * in between wins; the next run tries again), then changes the pod
 * template's hash so the Deployment rolls once. A value Eve did not mint
 * (a manifest that sets EVE_SERVICE_TOKEN, as the portal blanks it) is never
 * touched.
 */
@Injectable()
export class ServiceTokenRenewalService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ServiceTokenRenewalService.name);
  private readonly environments: ReturnType<typeof environmentQueries>;
  private firstTimer?: ReturnType<typeof setTimeout>;
  private timer?: ReturnType<typeof setInterval>;
  private running = false;
  /** The first run lists every token's expiry; later runs log renewals only. */
  private reported = false;

  constructor(
    @Inject('DB') db: Db,
    private readonly k8s: K8sService,
    @Inject(SERVICE_TOKEN_ISSUER) private readonly issuer: ServiceTokenIssuer,
  ) {
    this.environments = environmentQueries(db);
  }

  onModuleInit(): void {
    if (process.env.EVE_RUNTIME !== 'k8s') {
      this.logger.log('Service-token renewal skipped (EVE_RUNTIME is not k8s)');
      return;
    }
    const days = this.renewDays();
    if (days === 0) {
      this.logger.log('Service-token renewal off (EVE_SERVICE_TOKEN_RENEW_DAYS=0)');
      return;
    }
    this.logger.log(`Service-token renewal started (hourly; renews ${days} days before expiry)`);
    this.firstTimer = setTimeout(() => void this.renewSafe(), FIRST_RUN_DELAY_MS);
    this.timer = setInterval(() => void this.renewSafe(), HOUR_MS);
  }

  onModuleDestroy(): void {
    if (this.firstTimer) clearTimeout(this.firstTimer);
    if (this.timer) clearInterval(this.timer);
    this.firstTimer = undefined;
    this.timer = undefined;
  }

  /** The hourly pass over every deployed environment. Renews nothing with EVE_SERVICE_TOKEN_RENEW_DAYS=0. */
  async renewAll(): Promise<RenewedToken[]> {
    const days = this.renewDays();
    if (days === 0) return [];
    const renewed = await this.renew(await this.environments.listForServiceTokenRenewal(), days);
    this.reported = true;
    return renewed;
  }

  /**
   * One environment, now (after `eve env rotate-service-tokens`): its revoked
   * tokens and those signed by a retired key, and those expiring as the
   * hourly pass would. Nothing when the environment is not deployed.
   */
  async renewEnvironment(envId: string): Promise<RenewedToken[]> {
    return this.renew(await this.environments.listForServiceTokenRenewal(envId), this.renewDays());
  }

  private async renewSafe(): Promise<void> {
    if (this.running) return;
    this.running = true;
    try {
      await this.renewAll();
    } catch (err) {
      this.logger.error(`Service-token renewal failed: ${err instanceof Error ? err.message : err}`);
    } finally {
      this.running = false;
    }
  }

  private renewDays(): number {
    const raw = process.env.EVE_SERVICE_TOKEN_RENEW_DAYS?.trim();
    if (!raw) return DEFAULT_RENEW_DAYS;
    const days = Number(raw);
    if (!Number.isFinite(days) || days < 0) return DEFAULT_RENEW_DAYS;
    return Math.min(days, MAX_RENEW_DAYS);
  }

  private async renew(envs: ServiceTokenRenewalTarget[], days: number): Promise<RenewedToken[]> {
    if (envs.length === 0) return [];
    const signingKey = await this.issuer.signingKey();
    if (!signingKey) {
      this.logger.warn('The API did not name its signing key: tokens signed by a retired key wait for the next run');
    }
    const renewed: RenewedToken[] = [];
    for (const env of envs) {
      const policy: RenewalPolicy = {
        now: Math.floor(Date.now() / 1000),
        renewWithinSeconds: days * DAY_SECONDS,
        signingKey,
        notBefore: env.service_tokens_not_before
          ? Math.floor(new Date(env.service_tokens_not_before).getTime() / 1000)
          : null,
      };
      try {
        renewed.push(...await this.renewInEnvironment(env, policy));
      } catch (err) {
        this.logger.warn(`Service-token renewal failed in ${env.namespace}: ${err instanceof Error ? err.message : err}`);
      }
    }
    return renewed;
  }

  private async renewInEnvironment(env: ServiceTokenRenewalTarget, policy: RenewalPolicy): Promise<RenewedToken[]> {
    const secrets = await this.k8s.listSecrets(
      env.namespace,
      `${SERVICE_SECRETS_LABEL}=true,eve.project_id=${env.project_id},eve.env_id=${env.id}`,
    );
    const renewed: RenewedToken[] = [];
    for (const { name, labels } of secrets) {
      // Only what the applied release wrote: a service dropped from the
      // manifest keeps running, but its tokens lapse.
      if (labels['eve.release'] !== env.release_id) continue;
      renewed.push(...await this.renewSecret(env, name, policy));
    }
    return renewed;
  }

  private async renewSecret(
    env: ServiceTokenRenewalTarget,
    secretName: string,
    policy: RenewalPolicy,
  ): Promise<RenewedToken[]> {
    const secret = await this.k8s.readSecret(env.namespace, secretName);
    if (!secret) return [];
    const deployment = secret.annotations[SECRET_DEPLOYMENT_ANNOTATION];
    const component = secret.labels['eve.component'];

    const fresh: Record<string, string> = {};
    const renewed: RenewedToken[] = [];
    for (const [key, value] of Object.entries(secret.data)) {
      const held = heldToken(key, value, env, component);
      if (!held) continue;
      const reason = renewalReason(held.token, policy);
      if (!reason) {
        if (!this.reported) {
          this.logger.log(
            `${env.namespace}/${deployment ?? secretName} ${key}: expires ${iso(held.token.exp)}`
            + (policy.renewWithinSeconds > 0 ? `, renewed from ${iso(held.token.exp - policy.renewWithinSeconds)}` : ''),
          );
        }
        continue;
      }
      const token = held.kind === 'service'
        ? await this.issuer.mintServiceToken({
            projectId: env.project_id,
            orgId: env.org_id,
            envName: env.name,
            serviceName: held.serviceName,
            permissions: held.permissions,
            releaseId: env.release_id,
          })
        : await this.issuer.mintAppLinkToken({
            subscriptionId: held.subscriptionId,
            consumerPrincipal: held.principal,
            consumerProjectId: env.project_id,
            consumerEnv: env.name,
            producerEnv: held.producerEnv,
            ttlSeconds: TOKEN_TTL_SECONDS,
          });
      if (!token) {
        this.logger.warn(`Could not renew ${key} of ${env.namespace}/${secretName} (${reason}); the next run tries again`);
        continue;
      }
      fresh[key] = token;
      renewed.push({ env_id: env.id, namespace: env.namespace, secret: secretName, key, reason });
    }

    let rolledHash = secret.annotations[SECRETS_HASH_ANNOTATION];
    if (renewed.length > 0) {
      rolledHash = secretsHash({ ...secret.data, ...fresh });
      // The hash goes on the Secret too: a later run finishes a roll that
      // failed. A deploy replaces the Secret and drops it.
      const written = await this.k8s.patchSecretData(
        env.namespace,
        secretName,
        fresh,
        secret.resourceVersion,
        { [SECRETS_HASH_ANNOTATION]: rolledHash },
      );
      if (!written) {
        this.logger.log(`Secret ${env.namespace}/${secretName} changed since it was read; its tokens are renewed next run`);
        return [];
      }
      for (const item of renewed) {
        this.logger.log(`Renewed ${item.key} of ${env.namespace}/${secretName} (${item.reason})`);
      }
    }

    if (deployment && rolledHash) {
      await this.rollOnto(env.namespace, deployment, rolledHash);
    }
    return renewed;
  }

  /** Point the pod template's hash at the renewed values: the Deployment rolls once. */
  private async rollOnto(namespace: string, deployment: string, hash: string): Promise<void> {
    const annotations = await this.k8s.getDeploymentTemplateAnnotations(namespace, deployment);
    if (!annotations || annotations[SECRETS_HASH_ANNOTATION] === hash) return;
    await this.k8s.patchDeploymentTemplateAnnotations(namespace, deployment, { [SECRETS_HASH_ANNOTATION]: hash });
    this.logger.log(`Rolling ${namespace}/${deployment} onto its renewed tokens`);
  }
}

/**
 * The token under `key` when Eve minted it for this Secret's service in this
 * environment: EVE_SERVICE_TOKEN, or an EVE_APP_LINK_<ALIAS>_TOKEN with a
 * `service:<name>` principal. Anything else (a blank or a manifest's own
 * value) is left alone.
 */
function heldToken(
  key: string,
  value: string,
  env: ServiceTokenRenewalTarget,
  component: string | undefined,
): HeldToken | null {
  const isService = key === 'EVE_SERVICE_TOKEN';
  if (!isService && !APP_LINK_TOKEN_KEY.test(key)) return null;
  const token = decodeToken(value);
  if (!token) return null;
  const c = token.claims;
  const ownService = (name: unknown): name is string => {
    if (typeof name !== 'string' || component === undefined) return false;
    try {
      return toK8sLabelValue(name, 'component') === component;
    } catch {
      return false;
    }
  };

  if (isService) {
    if (c.type !== 'service' || c.project_id !== env.project_id || c.env_name !== env.name) return null;
    if (!ownService(c.service_name) || !Array.isArray(c.permissions)) return null;
    return {
      kind: 'service',
      token,
      serviceName: c.service_name,
      permissions: c.permissions.filter((p): p is string => typeof p === 'string'),
    };
  }

  const principal = c.consumer_principal;
  if (c.type !== 'app_link' || c.consumer_project_id !== env.project_id || c.consumer_env !== env.name) return null;
  if (typeof principal !== 'string' || !principal.startsWith('service:') || !ownService(principal.slice('service:'.length))) {
    return null;
  }
  if (typeof c.subscription_id !== 'string' || typeof c.producer_env !== 'string') return null;
  return { kind: 'app_link', token, subscriptionId: c.subscription_id, principal, producerEnv: c.producer_env };
}
