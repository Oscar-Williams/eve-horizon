import http from 'node:http';
import type { AddressInfo } from 'node:net';
import type express from 'express';
import { vi } from 'vitest';

/** The SSO as deployed on an https cluster: sso.eve.example, apps on *.eve.example. */
export const SSO_HOST = 'sso.eve.example';
export const SSO_ORIGIN = `https://${SSO_HOST}`;
export const GOTRUE_URL = 'http://gotrue.internal';
export const API_URL = 'http://api.internal';

const BASE_ENV: Record<string, string> = {
  EVE_DEFAULT_DOMAIN: 'eve.example',
  EVE_SSO_SECURE_COOKIES: 'true',
  EVE_API_URL: API_URL,
  SUPABASE_AUTH_URL: GOTRUE_URL,
  SUPABASE_ANON_KEY: 'anon-key',
  EVE_INTERNAL_API_KEY: 'internal-key',
  EVE_SIGNUP_ALLOWED_EMAIL_DOMAINS: '',
};

/** Load a fresh SSO app with this environment (config is read at module load). */
export async function loadSso(env: Record<string, string> = {}): Promise<express.Express> {
  vi.resetModules();
  for (const [key, value] of Object.entries({ ...BASE_ENV, ...env })) {
    vi.stubEnv(key, value);
  }
  const { createApp } = await import('../src/app.js');
  return createApp();
}

export interface UpstreamCall {
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | undefined;
}

export type UpstreamHandler = (call: UpstreamCall) => Response | Promise<Response>;

/**
 * Stand in for GoTrue and the Eve API: every outbound fetch is recorded and
 * answered by the first handler whose key prefixes `METHOD url`.
 */
export function stubUpstream(handlers: Record<string, UpstreamHandler>): { calls: UpstreamCall[] } {
  const calls: UpstreamCall[] = [];
  vi.stubGlobal('fetch', vi.fn(async (input: string | URL, init: RequestInit = {}) => {
    const headers: Record<string, string> = {};
    new Headers(init.headers ?? {}).forEach((value, key) => { headers[key] = value; });
    const call: UpstreamCall = {
      url: String(input),
      method: (init.method ?? 'GET').toUpperCase(),
      headers,
      body: typeof init.body === 'string' ? init.body : undefined,
    };
    calls.push(call);
    const key = Object.keys(handlers).find((prefix) => `${call.method} ${call.url}`.startsWith(prefix));
    if (!key) return new Response(`no upstream for ${call.method} ${call.url}`, { status: 599 });
    return handlers[key](call);
  }));
  return { calls };
}

export interface TestResponse {
  status: number;
  headers: http.IncomingHttpHeaders;
  text: string;
  cookies: string[];
}

/** Send one request to the app over a real socket (fetch is stubbed for upstreams). */
export async function send(
  app: express.Express,
  options: { method?: string; path: string; headers?: Record<string, string>; body?: string },
): Promise<TestResponse> {
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve) => server.once('listening', () => resolve()));
  const { port } = server.address() as AddressInfo;
  try {
    return await new Promise<TestResponse>((resolve, reject) => {
      const req = http.request(
        {
          host: '127.0.0.1',
          port,
          method: options.method ?? 'GET',
          path: options.path,
          headers: { host: SSO_HOST, ...options.headers },
        },
        (res) => {
          const chunks: Buffer[] = [];
          res.on('data', (chunk: Buffer) => chunks.push(chunk));
          res.on('end', () => {
            const setCookie = res.headers['set-cookie'];
            resolve({
              status: res.statusCode ?? 0,
              headers: res.headers,
              text: Buffer.concat(chunks).toString('utf8'),
              cookies: Array.isArray(setCookie) ? setCookie : setCookie ? [setCookie] : [],
            });
          });
        },
      );
      req.on('error', reject);
      if (options.body !== undefined) req.write(options.body);
      req.end();
    });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

/** A form-encoded POST body. */
export function form(fields: Record<string, string>): string {
  return new URLSearchParams(fields).toString();
}

/** The Set-Cookie line for a cookie name, if the response set or cleared it. */
export function cookieLine(cookies: string[], name: string, predicate: (line: string) => boolean = () => true): string | undefined {
  return cookies.find((line) => line.startsWith(`${name}=`) && predicate(line));
}

/** A GoTrue-shaped access token (unsigned: the SSO only decodes it; the API verifies). */
export function gotrueAccessToken(email: string): string {
  const encode = (value: object) => Buffer.from(JSON.stringify(value)).toString('base64url');
  const now = Math.floor(Date.now() / 1000);
  return `${encode({ alg: 'HS256', typ: 'JWT' })}.${encode({
    sub: '9f0c2b1a-1111-2222-3333-444455556666',
    email,
    aud: 'authenticated',
    role: 'authenticated',
    iat: now,
    exp: now + 3600,
  })}.signature`;
}
