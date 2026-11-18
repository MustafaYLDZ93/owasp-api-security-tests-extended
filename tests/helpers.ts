import { APIRequestContext } from '@playwright/test';

export const USERS = {
  userA: { email: 'user_a@test.com', password: 'Password123!', id: 10 },
  userB: { email: 'user_b@test.com', password: 'Password123!', id: 2 },
  admin: { email: 'admin@test.com', password: 'AdminPass123!', id: 3 },
};

export async function loginToken(request: APIRequestContext, email: string, password: string): Promise<string> {
  const res = await request.post('/api/auth/login', { data: { email, password } });
  const body = await res.json();
  return body.token;
}

export async function authHeader(
  request: APIRequestContext,
  user: { email: string; password: string },
): Promise<{ Authorization: string }> {
  const token = await loginToken(request, user.email, user.password);
  return { Authorization: `Bearer ${token}` };
}

/** Logs in via the cookie-session endpoint; returns the CSRF token issued at login. */
export async function sessionLogin(
  request: APIRequestContext,
  user: { email: string; password: string },
): Promise<string> {
  const res = await request.post('/api/session/login', { data: user });
  const body = await res.json();
  return body.csrfToken;
}

export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Extracts a single cookie's raw value from a `fetch` Response's Set-Cookie
 * header(s). The session-fixation/logout-invalidation tests use the global
 * `fetch` (not the Playwright `request` fixture's own cookie jar) so they
 * have full, unambiguous manual control over exactly which cookie value is
 * replayed on each call.
 */
export function extractCookieValue(res: Response, cookieName: string): string | null {
  const setCookies = typeof (res.headers as any).getSetCookie === 'function'
    ? (res.headers as any).getSetCookie()
    : [res.headers.get('set-cookie') ?? ''];
  for (const raw of setCookies) {
    const match = new RegExp(`^${cookieName}=([^;]*)`).exec(raw);
    if (match) return match[1];
  }
  return null;
}
