import { SECURE_COOKIES } from './config.js';

export function buildQuery(params: Record<string, string | undefined>): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value) query.set(key, value);
  }
  const text = query.toString();
  return text ? `?${text}` : '';
}

export function appendQueryParam(url: string, key: string, value: string): string {
  try {
    const parsed = new URL(url);
    if (!parsed.searchParams.has(key)) {
      parsed.searchParams.set(key, value);
    }
    return parsed.toString();
  } catch {
    return url;
  }
}

/** The SSO's own public origin, as the browser reached it. */
export function ssoOrigin(req: { get(name: string): string | undefined }): string {
  return `${SECURE_COOKIES ? 'https' : 'http'}://${req.get('host') ?? ''}`;
}
