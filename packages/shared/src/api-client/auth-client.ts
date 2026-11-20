import {
  loadConfig,
  getCorrelationHeaders,
} from '../index.js';
import { DEFAULT_AGENT_PERMISSIONS } from '../permissions.js';
import { hasInternalCredential, internalAuthHeaders } from './internal-keys.js';
import type { AccessBindingScope } from '../schemas/auth.js';

export interface JobTokenResult {
  access_token: string;
  token_type: string;
  expires_at: number;
}

/** 8 hours — long enough for extended jobs, well under 24h max. */
const DEFAULT_TTL_SECONDS = 28800;

export interface ServiceTokenResult {
  access_token: string;
  token_type: string;
  expires_at: number;
}

/** 90 days — refreshed on every deploy */
const DEFAULT_SERVICE_TTL_SECONDS = 90 * 24 * 60 * 60;

export interface AppLinkTokenResult {
  access_token: string;
  token_type: string;
  expires_at: number;
}

/** 1 hour for job-surface app-link tokens. Service deploys override to 90d. */
const DEFAULT_APP_LINK_TTL_SECONDS = 60 * 60;

export interface ServiceTokenParams {
  projectId: string;
  orgId: string;
  envName: string;
  serviceName: string;
  permissions?: string[];
  ttlSeconds?: number;
  /** The release being deployed: the API grants what its manifest declares for the service. */
  releaseId?: string;
}

/** Why no token was minted: the API's HTTP status, or null when the API could not be asked or answered nothing usable. */
export interface MintFailure {
  status: number | null;
}

/**
 * Mint a service token via the internal API.
 *
 * The token allows a deployed app service to call the Eve API,
 * scoped to the service's org/project/environment with only the
 * permissions specified (or sensible defaults).
 */
export async function mintServiceToken(params: ServiceTokenParams): Promise<ServiceTokenResult | null> {
  const result = await requestServiceToken(params);
  return 'access_token' in result ? result : null;
}

/** mintServiceToken, saying why it minted nothing (a 404 names a project, env or release the API did not find). */
export async function requestServiceToken(params: ServiceTokenParams): Promise<ServiceTokenResult | MintFailure> {
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
  } catch {
    // Config not available (e.g. unit tests) — silently skip
    return { status: null };
  }

  if (!hasInternalCredential() || !config.EVE_API_URL) {
    console.warn('[auth-client] Missing an internal key or EVE_API_URL — cannot mint service token');
    return { status: null };
  }

  try {
    const url = `${config.EVE_API_URL}/internal/auth/mint-service-token`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...internalAuthHeaders(),
        ...getCorrelationHeaders(),
      },
      body: JSON.stringify({
        project_id: params.projectId,
        org_id: params.orgId,
        env_name: params.envName,
        service_name: params.serviceName,
        permissions: params.permissions,
        ttl_seconds: params.ttlSeconds ?? DEFAULT_SERVICE_TTL_SECONDS,
        ...(params.releaseId ? { release_id: params.releaseId } : {}),
      }),
    });

    if (!response.ok) {
      console.warn(`[auth-client] mint-service-token returned ${response.status}: ${response.statusText}`);
      return { status: response.status };
    }

    const result = await response.json() as ServiceTokenResult;
    return typeof result?.access_token === 'string' ? result : { status: null };
  } catch (err) {
    console.warn(`[auth-client] Failed to mint service token: ${err instanceof Error ? err.message : err}`);
    return { status: null };
  }
}

/**
 * Mint a job token via the internal API.
 *
 * The token allows the agent to call `eve` CLI commands that hit the
 * public API on behalf of the job's actor user, scoped to the job's
 * org/project with only the permissions listed above.
 */
export async function mintJobToken(
  jobId: string,
  options?: {
    permissions?: string[];
    scope?: AccessBindingScope;
    ttlSeconds?: number;
    /** The running attempt to bind the token to; it stops working when that attempt ends. */
    attemptId?: string;
  },
): Promise<JobTokenResult | null> {
  const config = loadConfig();

  if (!hasInternalCredential() || !config.EVE_API_URL) {
    console.warn('[auth-client] Missing an internal key or EVE_API_URL — cannot mint job token');
    return null;
  }

  try {
    const url = `${config.EVE_API_URL}/internal/auth/mint-job-token`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...internalAuthHeaders(),
        ...getCorrelationHeaders(),
      },
      body: JSON.stringify({
        job_id: jobId,
        permissions: options?.permissions ?? DEFAULT_AGENT_PERMISSIONS,
        scope: options?.scope,
        ttl_seconds: options?.ttlSeconds ?? DEFAULT_TTL_SECONDS,
        ...(options?.attemptId ? { attempt_id: options.attemptId } : {}),
      }),
    });

    if (!response.ok) {
      console.warn(`[auth-client] mint-job-token returned ${response.status}: ${response.statusText}`);
      return null;
    }

    const json = await response.json();
    return json as JobTokenResult;
  } catch (err) {
    console.warn(`[auth-client] Failed to mint job token: ${err instanceof Error ? err.message : err}`);
    return null;
  }
}

export async function mintAppLinkToken(
  params: {
    subscriptionId: string;
    consumerPrincipal: string;
    /** The consumer's project; required unless the principal is `job:<id>`. */
    consumerProjectId?: string | null;
    consumerEnv?: string | null;
    producerEnv?: string | null;
    ttlSeconds?: number;
    /** For a `job:<id>` principal: the running attempt to bind the token to. */
    attemptId?: string;
  },
): Promise<AppLinkTokenResult | null> {
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
  } catch {
    return null;
  }

  if (!hasInternalCredential() || !config.EVE_API_URL) {
    console.warn('[auth-client] Missing an internal key or EVE_API_URL — cannot mint app-link token');
    return null;
  }

  try {
    const url = `${config.EVE_API_URL}/internal/auth/mint-app-link-token`;
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...internalAuthHeaders(),
        ...getCorrelationHeaders(),
      },
      body: JSON.stringify({
        subscription_id: params.subscriptionId,
        consumer_principal: params.consumerPrincipal,
        ...(params.consumerProjectId ? { consumer_project_id: params.consumerProjectId } : {}),
        consumer_env: params.consumerEnv ?? null,
        producer_env: params.producerEnv ?? null,
        ttl_seconds: params.ttlSeconds ?? DEFAULT_APP_LINK_TTL_SECONDS,
        ...(params.attemptId ? { attempt_id: params.attemptId } : {}),
      }),
    });

    if (!response.ok) {
      console.warn(`[auth-client] mint-app-link-token returned ${response.status}: ${response.statusText}`);
      return null;
    }

    return await response.json() as AppLinkTokenResult;
  } catch (err) {
    console.warn(`[auth-client] Failed to mint app-link token: ${err instanceof Error ? err.message : err}`);
    return null;
  }
}

export interface SigningKeyResult {
  kid: string;
  /** The public key as a JWK. */
  public_key: Record<string, unknown>;
}

/**
 * The key the API signs tokens with now (internal API). The worker renews a
 * deployed service's token signed by any other key. Null when the API cannot
 * be reached or names none.
 */
export async function fetchSigningKey(): Promise<SigningKeyResult | null> {
  let config: ReturnType<typeof loadConfig>;
  try {
    config = loadConfig();
  } catch {
    return null;
  }

  if (!hasInternalCredential() || !config.EVE_API_URL) {
    console.warn('[auth-client] Missing an internal key or EVE_API_URL — cannot read the signing key');
    return null;
  }

  try {
    const response = await fetch(`${config.EVE_API_URL}/internal/auth/signing-key`, {
      headers: { ...internalAuthHeaders(), ...getCorrelationHeaders() },
    });
    if (!response.ok) {
      console.warn(`[auth-client] signing-key returned ${response.status}: ${response.statusText}`);
      return null;
    }
    const body = await response.json() as Partial<SigningKeyResult>;
    return typeof body.kid === 'string' && body.public_key && typeof body.public_key === 'object'
      ? { kid: body.kid, public_key: body.public_key }
      : null;
  } catch (err) {
    console.warn(`[auth-client] Failed to read the signing key: ${err instanceof Error ? err.message : err}`);
    return null;
  }
}
