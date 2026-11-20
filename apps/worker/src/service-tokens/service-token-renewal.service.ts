import { createPublicKey, verify as verifySignature, type JsonWebKey, type KeyObject } from 'node:crypto';
import { Inject, Injectable, Logger, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { environmentQueries, eventQueries, type Db, type ServiceTokenRenewalTarget } from '@eve/db';
import {
  fetchSigningKey,
  generateEventId,
  mintAppLinkToken,
  requestServiceToken,
  serviceTokenFloor,
  toK8sLabelValue,
} from '@eve/shared';
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
/** The hourly pass renews and rolls at most this many Deployments (EVE_SERVICE_TOKEN_RENEW_BATCH). */
const DEFAULT_RENEW_BATCH = 3;
/**
 * A Recreate Deployment (a database, a ReadWriteOnce volume, stable egress)
 * stops serving while it rolls, so its pods roll onto renewed tokens only once
 * the token they hold is revoked or this close to expiry.
 */
const RECREATE_ROLL_WITHIN_SECONDS = 7 * DAY_SECONDS;
/** A roll not done this long after it started is stuck: the deploy action's default readiness wait. */
const ROLLOUT_TIMEOUT_MS = 180 * 1000;
const APP_LINK_TOKEN_KEY = /^EVE_APP_LINK_[A-Z0-9_]+_TOKEN$/;

/**
 * Secret annotation: when a held-back Recreate roll falls due, 7 days before
 * the token its pods hold expires. Only read while the pods are behind the
 * Secret (its hash differs from the pod template's).
 */
export const TOKENS_ROLL_BY_ANNOTATION = 'eve.tokens-roll-by';
/** Event recorded for a renewal roll that has not finished by the next pass past the deploy timeout. */
export const ROLLOUT_STUCK_EVENT = 'system.service_token.rollout_stuck';

export const SERVICE_TOKEN_ISSUER = 'SERVICE_TOKEN_ISSUER';

export type RenewalReason = 'expiring' | 'retired_key' | 'revoked';

export interface RenewedToken {
  env_id: string;
  namespace: string;
  secret: string;
  key: string;
  reason: RenewalReason;
}

/**
 * What a pass did with the tokens it took on: renewed (written, and rolled or
 * held back); conflicted (their Secret was written in between, by a deploy:
 * the next pass looks again); failed (not renewed, or renewed but not rolled
 * onto: the next pass tries again).
 */
export interface RenewalReport {
  renewed: RenewedToken[];
  conflicted: RenewedToken[];
  failed: Array<RenewedToken & { error: string }>;
}

const emptyReport = (): RenewalReport => ({ renewed: [], conflicted: [], failed: [] });

interface SigningKey {
  kid: string;
  publicKey: KeyObject;
}

/** The API refused to mint: its HTTP status. */
export interface MintRefusal {
  status: number;
}

/** What renewal asks the API for: the key it signs with now, and fresh tokens. */
export interface ServiceTokenIssuer {
  signingKey(): Promise<SigningKey | null>;
  /** A token; the API's refusal (a 404 names a project, environment or release it did not find); or null. */
  mintServiceToken(params: {
    projectId: string;
    orgId: string;
    envName: string;
    serviceName: string;
    permissions: string[];
    releaseId: string;
  }): Promise<string | MintRefusal | null>;
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

  async mintServiceToken(params: Parameters<ServiceTokenIssuer['mintServiceToken']>[0]): Promise<string | MintRefusal | null> {
    const result = await requestServiceToken({ ...params, ttlSeconds: TOKEN_TTL_SECONDS });
    if ('access_token' in result) return result.access_token;
    return result.status !== null ? { status: result.status } : null;
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
  /** The environment's floor (its creation or service_tokens_not_before), in seconds. */
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

/** A service Secret, as read. */
type ServiceSecret = NonNullable<Awaited<ReturnType<K8sService['readSecret']>>>;
/** A Deployment's strategy, template annotations and rollout state, as read. */
type DeploymentRollout = NonNullable<Awaited<ReturnType<K8sService['readDeploymentRollout']>>>;

/** One service Secret a pass acts on: tokens to renew, a roll its pods are owed, or both. */
interface SecretWork {
  env: ServiceTokenRenewalTarget;
  policy: RenewalPolicy;
  secretName: string;
  secret: ServiceSecret;
  deployment?: string;
  rollout: DeploymentRollout | null;
  /** The Secret's values are newer than the pods' (a roll held back, or one that failed). */
  podsBehind: boolean;
  /** Tokens to renew, and why. */
  due: Array<{ key: string; held: HeldToken; reason: RenewalReason }>;
  /** Seconds: the expiry of the most pressing token this work answers; -Infinity for a revoked one. */
  urgency: number;
}

/** A roll renewal started, checked on a later pass. */
interface StartedRoll {
  env: ServiceTokenRenewalTarget;
  deployment: string;
  hash: string;
  startedAt: number;
}

const isRefusal = (value: string | MintRefusal | null): value is MintRefusal =>
  typeof value === 'object' && value !== null;

const byUrgency = (a: SecretWork, b: SecretWork) => (a.urgency === b.urgency ? 0 : a.urgency < b.urgency ? -1 : 1);

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
 *
 * Rolls are unattended, so the hourly pass acts on at most
 * EVE_SERVICE_TOKEN_RENEW_BATCH Deployments (default 3), the soonest to
 * expire first; the rest wait for the next pass. A Recreate Deployment is
 * down while it rolls: its Secret is renewed, but it rolls only once the
 * token its pods hold is revoked or within 7 days of expiry (or when it
 * restarts by itself). The next pass checks each roll it started and warns,
 * with a `system.service_token.rollout_stuck` event, about one not done past
 * the deploy timeout. A rotation renews its whole environment at once.
 */
@Injectable()
export class ServiceTokenRenewalService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(ServiceTokenRenewalService.name);
  private readonly environments: ReturnType<typeof environmentQueries>;
  private readonly events: ReturnType<typeof eventQueries>;
  private firstTimer?: ReturnType<typeof setTimeout>;
  private timer?: ReturnType<typeof setInterval>;
  private running = false;
  /** The first run lists every token's expiry; later runs log renewals only. */
  private reported = false;
  /** Rolls this worker started, by `namespace/deployment`, until they are seen done. */
  private readonly rolls = new Map<string, StartedRoll>();

  constructor(
    @Inject('DB') db: Db,
    private readonly k8s: K8sService,
    @Inject(SERVICE_TOKEN_ISSUER) private readonly issuer: ServiceTokenIssuer,
  ) {
    this.environments = environmentQueries(db);
    this.events = eventQueries(db);
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
    this.logger.log(
      `Service-token renewal started (hourly; renews ${days} days before expiry, at most ${this.renewBatch()} Deployments a pass)`,
    );
    this.firstTimer = setTimeout(() => void this.renewSafe(), FIRST_RUN_DELAY_MS);
    this.timer = setInterval(() => void this.renewSafe(), HOUR_MS);
  }

  onModuleDestroy(): void {
    if (this.firstTimer) clearTimeout(this.firstTimer);
    if (this.timer) clearInterval(this.timer);
    this.firstTimer = undefined;
    this.timer = undefined;
  }

  /**
   * The hourly pass over every deployed environment: at most
   * EVE_SERVICE_TOKEN_RENEW_BATCH Deployments, the soonest to expire first.
   * Renews nothing with EVE_SERVICE_TOKEN_RENEW_DAYS=0.
   */
  async renewAll(): Promise<RenewalReport> {
    const days = this.renewDays();
    if (days === 0) return emptyReport();
    const report = await this.renew(await this.environments.listForServiceTokenRenewal(), days, 'hourly');
    this.reported = true;
    return report;
  }

  /**
   * One environment, now (after `eve env rotate-service-tokens`): its revoked
   * tokens and those signed by a retired key, and those expiring as the
   * hourly pass would, all at once. Nothing when the environment is not
   * deployed. Throws when the environment's Secrets cannot be read.
   */
  async renewEnvironment(envId: string): Promise<RenewalReport> {
    return this.renew(await this.environments.listForServiceTokenRenewal(envId), this.renewDays(), 'rotation');
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

  private renewBatch(): number {
    const batch = Number(process.env.EVE_SERVICE_TOKEN_RENEW_BATCH?.trim() || DEFAULT_RENEW_BATCH);
    return Number.isInteger(batch) && batch >= 1 ? batch : DEFAULT_RENEW_BATCH;
  }

  /**
   * `hourly`: every deployed environment, at most EVE_SERVICE_TOKEN_RENEW_BATCH
   * Secrets, and an environment that cannot be read waits for the next pass.
   * `rotation`: one environment a person asked for, all of it, or an error.
   */
  private async renew(envs: ServiceTokenRenewalTarget[], days: number, mode: 'hourly' | 'rotation'): Promise<RenewalReport> {
    await this.checkRolls();
    if (envs.length === 0) return emptyReport();
    const signingKey = await this.issuer.signingKey();
    if (!signingKey) {
      this.logger.warn('The API did not name its signing key: tokens signed by a retired key wait for the next run');
    }

    const work: SecretWork[] = [];
    for (const env of envs) {
      const policy: RenewalPolicy = {
        now: Math.floor(Date.now() / 1000),
        renewWithinSeconds: days * DAY_SECONDS,
        signingKey,
        // The floor the API holds the environment's tokens to.
        notBefore: serviceTokenFloor(env),
      };
      try {
        work.push(...await this.survey(env, policy));
      } catch (err) {
        if (mode === 'rotation') throw err;
        this.logger.warn(`Service-token renewal failed in ${env.namespace}: ${errorText(err)}`);
      }
    }

    work.sort(byUrgency);
    const batch = mode === 'hourly' ? this.renewBatch() : work.length;
    const chosen = work.slice(0, batch);
    if (work.length > chosen.length) {
      this.logger.log(
        `${work.length - chosen.length} more service Secret(s) wait for the next pass (at most ${batch} a pass, EVE_SERVICE_TOKEN_RENEW_BATCH)`,
      );
    }
    const report = emptyReport();
    for (const item of chosen) {
      try {
        const done = await this.act(item);
        report.renewed.push(...done.renewed);
        report.conflicted.push(...done.conflicted);
        report.failed.push(...done.failed);
      } catch (err) {
        this.logger.warn(`Service-token renewal failed for ${item.env.namespace}/${item.secretName}: ${errorText(err)}`);
        report.failed.push(...item.due.map(({ key, reason }) => ({
          ...tokenAt(item, key, reason),
          error: errorText(err),
        })));
      }
    }
    return report;
  }

  /** The Secrets of one environment that need work now, read but not yet touched. */
  private async survey(env: ServiceTokenRenewalTarget, policy: RenewalPolicy): Promise<SecretWork[]> {
    const secrets = await this.k8s.listSecrets(
      env.namespace,
      `${SERVICE_SECRETS_LABEL}=true,eve.project_id=${env.project_id},eve.env_id=${env.id}`,
    );
    const work: SecretWork[] = [];
    for (const { name, labels } of secrets) {
      // Only what the applied release wrote: a service dropped from the
      // manifest keeps running, but its tokens lapse.
      if (labels['eve.release'] !== env.release_id) continue;
      const item = await this.surveySecret(env, name, policy);
      if (item) work.push(item);
    }
    return work;
  }

  private async surveySecret(env: ServiceTokenRenewalTarget, secretName: string, policy: RenewalPolicy): Promise<SecretWork | null> {
    const secret = await this.k8s.readSecret(env.namespace, secretName);
    if (!secret) return null;
    const deployment = secret.annotations[SECRET_DEPLOYMENT_ANNOTATION];
    const component = secret.labels['eve.component'];

    const due: SecretWork['due'] = [];
    for (const [key, value] of Object.entries(secret.data)) {
      const held = heldToken(key, value, env, component);
      if (!held) continue;
      const reason = renewalReason(held.token, policy);
      if (reason) {
        due.push({ key, held, reason });
      } else if (!this.reported) {
        this.logger.log(
          `${env.namespace}/${deployment ?? secretName} ${key}: expires ${iso(held.token.exp)}`
          + (policy.renewWithinSeconds > 0 ? `, renewed from ${iso(held.token.exp - policy.renewWithinSeconds)}` : ''),
        );
      }
    }

    // The hash goes on the Secret when renewal writes it; a deploy replaces
    // the Secret and drops it. Without it the pods run the Secret's values.
    const secretHash = secret.annotations[SECRETS_HASH_ANNOTATION];
    if (due.length === 0 && !secretHash) return null;
    const rollout = deployment ? await this.k8s.readDeploymentRollout(env.namespace, deployment) : null;
    const podsBehind = Boolean(secretHash && rollout && rollout.templateAnnotations[SECRETS_HASH_ANNOTATION] !== secretHash);

    let urgency = Math.min(...due.map(({ held, reason }) => (reason === 'revoked' ? -Infinity : held.token.exp)));
    if (podsBehind) {
      const rollBy = heldBackUntil(secret, rollout);
      if (rollBy !== null && rollBy > policy.now) {
        if (!this.reported) {
          this.logger.log(`${env.namespace}/${deployment} (Recreate) rolls onto its renewed tokens by ${iso(rollBy)}`);
        }
      } else {
        // A roll owed: held back until now, or one that failed. The pods'
        // token expires 7 days after a roll-by; unknown otherwise.
        urgency = Math.min(urgency, rollBy !== null ? rollBy + RECREATE_ROLL_WITHIN_SECONDS : -Infinity);
      }
    }
    if (urgency === Infinity) return null;
    return { env, policy, secretName, secret, deployment, rollout, podsBehind, due, urgency };
  }

  /** Renew a Secret's due tokens, then roll its Deployment onto them, or hold a Recreate one back. */
  private async act(work: SecretWork): Promise<RenewalReport> {
    const { env, secretName, secret, deployment, rollout, policy } = work;
    const fresh: Record<string, string> = {};
    const renewed: RenewedToken[] = [];
    const failed: RenewalReport['failed'] = [];
    let pressing = false;
    let replacedExpiry = Infinity;
    for (const { key, held, reason } of work.due) {
      const token = await this.mint(env, held, `${env.namespace}/${secretName} ${key}`);
      if (!token) {
        this.logger.warn(`Could not renew ${key} of ${env.namespace}/${secretName} (${reason}); the next run tries again`);
        failed.push({ ...tokenAt(work, key, reason), error: 'the API minted no token' });
        continue;
      }
      fresh[key] = token;
      renewed.push(tokenAt(work, key, reason));
      pressing ||= reason === 'revoked' || held.token.exp - policy.now <= RECREATE_ROLL_WITHIN_SECONDS;
      replacedExpiry = Math.min(replacedExpiry, held.token.exp);
    }

    // When the pods are behind, they hold tokens older than the Secret's:
    // their roll-by stands. Otherwise they hold the tokens being replaced.
    const recreate = rollout?.strategy === 'Recreate';
    const heldBack = heldBackUntil(secret, rollout);
    const rollBy = work.podsBehind ? heldBack : replacedExpiry - RECREATE_ROLL_WITHIN_SECONDS;
    const holdBack = recreate && !pressing && rollBy !== null && rollBy > policy.now;

    let rolledHash = secret.annotations[SECRETS_HASH_ANNOTATION];
    if (renewed.length > 0) {
      rolledHash = secretsHash({ ...secret.data, ...fresh });
      // The hash goes on the Secret too: a later run finishes a roll that
      // failed or was held back. A deploy replaces the Secret and drops it.
      const annotations: Record<string, string | null> = { [SECRETS_HASH_ANNOTATION]: rolledHash };
      if (holdBack) annotations[TOKENS_ROLL_BY_ANNOTATION] = iso(rollBy!);
      else if (secret.annotations[TOKENS_ROLL_BY_ANNOTATION] !== undefined) annotations[TOKENS_ROLL_BY_ANNOTATION] = null;
      const written = await this.k8s.patchSecretData(env.namespace, secretName, fresh, secret.resourceVersion, annotations);
      if (!written) {
        this.logger.log(`Secret ${env.namespace}/${secretName} changed since it was read; its tokens are renewed next run`);
        return { renewed: [], conflicted: renewed, failed };
      }
      for (const item of renewed) {
        this.logger.log(`Renewed ${item.key} of ${env.namespace}/${secretName} (${item.reason})`);
      }
    }

    if (!deployment || !rollout || !rolledHash) return { renewed, conflicted: [], failed };
    if (holdBack) {
      if (renewed.length > 0) {
        this.logger.log(
          `${env.namespace}/${deployment} uses the Recreate strategy and stops serving while it rolls, so it is not rolled now: `
          + `its pods roll onto the renewed tokens by ${iso(rollBy!)}, 7 days before the token they hold expires, `
          + 'or at once if that token is revoked',
        );
      }
      return { renewed, conflicted: [], failed };
    }
    try {
      await this.rollOnto(env, deployment, rollout, rolledHash);
    } catch (err) {
      // The Secret holds the new tokens, the pods the old ones: the next pass rolls it.
      this.logger.warn(`${env.namespace}/${deployment} did not roll onto its renewed tokens: ${errorText(err)}; the next run tries again`);
      const error = `renewed in the Secret, but ${deployment} did not roll onto it: ${errorText(err)}`;
      return { renewed: [], conflicted: [], failed: [...failed, ...renewed.map((item) => ({ ...item, error }))] };
    }
    return { renewed, conflicted: [], failed };
  }

  private async mint(env: ServiceTokenRenewalTarget, held: HeldToken, what: string): Promise<string | null> {
    if (held.kind === 'app_link') {
      return this.issuer.mintAppLinkToken({
        subscriptionId: held.subscriptionId,
        consumerPrincipal: held.principal,
        consumerProjectId: env.project_id,
        consumerEnv: env.name,
        producerEnv: held.producerEnv,
        ttlSeconds: TOKEN_TTL_SECONDS,
      });
    }
    const params = {
      projectId: env.project_id,
      orgId: env.org_id,
      envName: env.name,
      serviceName: held.serviceName,
      permissions: held.permissions,
      releaseId: env.release_id,
    };
    const minted = await this.issuer.mintServiceToken(params);
    if (!isRefusal(minted) || minted.status !== 404) return isRefusal(minted) ? null : minted;

    // The applied release's row is gone (it is read for the service's
    // permissions): without a way out this would fail every hour.
    const fallback = env.current_release_id && env.current_release_id !== env.release_id ? env.current_release_id : null;
    this.logger.error(
      `Could not renew ${what} of environment ${env.name} (${env.id}, project ${env.project_id}): `
      + `the API did not find release ${env.release_id}, the one applied there; `
      + (fallback ? `minting against its current release ${fallback}` : 'deploy the environment again to renew it'),
    );
    if (!fallback) return null;
    const retried = await this.issuer.mintServiceToken({ ...params, releaseId: fallback });
    return isRefusal(retried) ? null : retried;
  }

  /** Point the pod template's hash at the renewed values: the Deployment rolls once. */
  private async rollOnto(
    env: ServiceTokenRenewalTarget,
    deployment: string,
    rollout: DeploymentRollout,
    hash: string,
  ): Promise<void> {
    if (rollout.templateAnnotations[SECRETS_HASH_ANNOTATION] === hash) return;
    await this.k8s.patchDeploymentTemplateAnnotations(env.namespace, deployment, { [SECRETS_HASH_ANNOTATION]: hash });
    this.rolls.set(`${env.namespace}/${deployment}`, { env, deployment, hash, startedAt: Date.now() });
    this.logger.log(`Rolling ${env.namespace}/${deployment} onto its renewed tokens`);
  }

  /**
   * The rolls this worker started: done ones are forgotten; one not done
   * past the deploy timeout gets a warning and an event, once. A Deployment
   * that is gone, or that a deploy has rolled since, is forgotten.
   */
  private async checkRolls(): Promise<void> {
    for (const [key, roll] of [...this.rolls]) {
      let rollout: DeploymentRollout | null;
      try {
        rollout = await this.k8s.readDeploymentRollout(roll.env.namespace, roll.deployment);
      } catch (err) {
        this.logger.warn(`Could not check the roll of ${key}: ${err instanceof Error ? err.message : err}`);
        continue;
      }
      if (!rollout || rollout.templateAnnotations[SECRETS_HASH_ANNOTATION] !== roll.hash) {
        this.rolls.delete(key);
        continue;
      }
      if (rollout.rolledOut) {
        this.rolls.delete(key);
        this.logger.log(`${key} rolled onto its renewed tokens`);
        continue;
      }
      const elapsedMs = Date.now() - roll.startedAt;
      if (elapsedMs < ROLLOUT_TIMEOUT_MS) continue;
      this.rolls.delete(key);
      this.logger.warn(
        `${key} has not finished rolling onto its renewed tokens ${Math.round(elapsedMs / 60_000)} min after renewal started it `
        + `(deploy timeout ${ROLLOUT_TIMEOUT_MS / 1000} s); pods of the old ReplicaSet may still hold the old tokens: `
        + `kubectl -n ${roll.env.namespace} rollout status deployment/${roll.deployment}`,
      );
      await this.recordStuckRoll(roll, elapsedMs);
    }
  }

  private async recordStuckRoll(roll: StartedRoll, elapsedMs: number): Promise<void> {
    try {
      await this.events.create({
        id: generateEventId(),
        project_id: roll.env.project_id,
        type: ROLLOUT_STUCK_EVENT,
        source: 'system',
        env_name: roll.env.name,
        ref_sha: null,
        ref_branch: null,
        actor_type: 'system',
        actor_id: 'worker',
        payload_json: {
          env_id: roll.env.id,
          namespace: roll.env.namespace,
          deployment: roll.deployment,
          started_at: new Date(roll.startedAt).toISOString(),
          elapsed_seconds: Math.round(elapsedMs / 1000),
          timeout_seconds: ROLLOUT_TIMEOUT_MS / 1000,
        },
        dedupe_key: `service_token_rollout_stuck:${roll.env.id}:${roll.deployment}:${roll.hash}`,
      });
    } catch (err) {
      this.logger.warn(`Could not record ${ROLLOUT_STUCK_EVENT} for ${roll.env.namespace}/${roll.deployment}: ${err instanceof Error ? err.message : err}`);
    }
  }
}

const errorText = (err: unknown) => (err instanceof Error ? err.message : String(err));

function tokenAt(work: Pick<SecretWork, 'env' | 'secretName'>, key: string, reason: RenewalReason): RenewedToken {
  return { env_id: work.env.id, namespace: work.env.namespace, secret: work.secretName, key, reason };
}

/**
 * Seconds: when a Recreate Deployment's held-back roll falls due, from its
 * Secret's roll-by. Null for any other Deployment, or when none is recorded
 * (a roll that failed): it rolls now.
 */
function heldBackUntil(secret: ServiceSecret, rollout: DeploymentRollout | null): number | null {
  if (rollout?.strategy !== 'Recreate') return null;
  const raw = secret.annotations[TOKENS_ROLL_BY_ANNOTATION];
  const ms = raw ? new Date(raw).getTime() : NaN;
  return Number.isFinite(ms) ? Math.floor(ms / 1000) : null;
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
