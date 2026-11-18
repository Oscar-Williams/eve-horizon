/**
 * App audience tokens: user tokens the SSO gives a deployed app under the
 * strict instance profile. Their `aud` names the app
 * (`eve-app:<project_id>:<env>`, or `eve-app:<project_id>` when the app's
 * address names no environment), and the API accepts them only on the app
 * sign-in routes, only with a matching `X-Eve-Audience` header and only for
 * that project.
 */

export const APP_AUDIENCE_PREFIX = 'eve-app:';

/** The request header an app sends with its audience token. */
export const APP_AUDIENCE_HEADER = 'x-eve-audience';

/** How long an app audience token lasts. */
export const APP_AUDIENCE_TOKEN_TTL_SECONDS = 60 * 60;

export interface AppAudience {
  projectId: string;
  envName: string | null;
}

export function formatAppAudience(projectId: string, envName: string | null): string {
  return envName ? `${APP_AUDIENCE_PREFIX}${projectId}:${envName}` : `${APP_AUDIENCE_PREFIX}${projectId}`;
}

/** The project and environment an `eve-app:` audience names, or null for any other value. */
export function parseAppAudience(aud: unknown): AppAudience | null {
  if (typeof aud !== 'string' || !aud.startsWith(APP_AUDIENCE_PREFIX)) return null;
  const [projectId, envName, ...rest] = aud.slice(APP_AUDIENCE_PREFIX.length).split(':');
  if (!projectId || rest.length > 0 || envName === '') return null;
  return { projectId, envName: envName ?? null };
}

/** What a request offers to be checked against an app audience token. */
export interface AppAudienceRequest {
  /** The request's X-Eve-Audience header. */
  header: string | undefined;
  /** Every project id the request names; each must be the token's project. */
  projectIds: string[];
}

type RequestLike = {
  headers?: Record<string, string | string[] | undefined>;
  query?: Record<string, unknown>;
  body?: unknown;
};

/** The audience header and every `project_id` in the query and body of a request. */
export function appAudienceRequestFrom(request: RequestLike, extraProjectIds: unknown[] = []): AppAudienceRequest {
  const body = request.body && typeof request.body === 'object' ? (request.body as Record<string, unknown>) : {};
  return {
    header: firstString(request.headers?.[APP_AUDIENCE_HEADER]),
    projectIds: [request.query?.project_id, body.project_id, ...extraProjectIds].flatMap(stringValues),
  };
}

function firstString(value: unknown): string | undefined {
  if (Array.isArray(value)) return firstString(value[0]);
  return typeof value === 'string' ? value : undefined;
}

function stringValues(value: unknown): string[] {
  if (Array.isArray(value)) return value.flatMap(stringValues);
  if (value === undefined || value === null || value === '') return [];
  return [String(value)];
}
