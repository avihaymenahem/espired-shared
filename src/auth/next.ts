// @espired/shared/auth/next — Next.js App Router adapter.
// Uses only the Web `Request` / `Response` types; nothing here imports `next`.

import { readCookie, type Oidc, type OidcClaims } from './core.js';
import { defaultOnError, describeError, ERROR_HEADERS } from './http.js';

export type RouteHandler = (req: Request) => Promise<Response>;

export interface NextLoginContext {
  req: Request;
  /** Safe same-origin path the user asked for (defaults to `/`). */
  next: string;
  /** Raw ID token, e.g. to keep for `buildLogoutUrl({ idTokenHint })`. */
  idToken: string;
}

export interface LoginHandlerOptions {
  /** Called for every failure. Defaults to logging 5xx errors with console.error. */
  onError?(err: unknown, req: Request): void;
}

export interface CallbackHandlerOptions extends LoginHandlerOptions {
  oidc: Oidc;
  /**
   * Called after a verified login. Link the account, start your session and return the
   * response, e.g. `NextResponse.redirect(new URL(ctx.next, APP_URL))` with your session
   * cookie set on it. Throw `OidcAccessDenied` to answer 403.
   */
  onLogin(claims: OidcClaims, ctx: NextLoginContext): Response | Promise<Response>;
}

function isResponse(value: unknown): value is Response {
  const candidate = value as Response | null | undefined;
  return (
    typeof candidate === 'object' &&
    candidate !== null &&
    typeof candidate.status === 'number' &&
    typeof candidate.headers?.append === 'function'
  );
}

function errorResponse(err: unknown, req: Request, onError: (err: unknown, req: Request) => void, clearCookie?: string): Response {
  try {
    onError(err, req);
  } catch {
    // a broken error hook must not break the response
  }
  const { status, message } = describeError(err);
  const headers = new Headers(ERROR_HEADERS);
  if (clearCookie) headers.append('Set-Cookie', clearCookie);
  return new Response(message, { status, headers });
}

/** Appends a Set-Cookie header, copying the response if its headers are immutable (e.g. `Response.redirect`). */
function withSetCookie(response: Response, cookie: string): Response {
  try {
    response.headers.append('Set-Cookie', cookie);
    if (!response.headers.has('Cache-Control')) response.headers.set('Cache-Control', 'no-store');
    return response;
  } catch {
    const headers = new Headers(response.headers);
    headers.append('Set-Cookie', cookie);
    if (!headers.has('Cache-Control')) headers.set('Cache-Control', 'no-store');
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  }
}

/** `GET /login?next=` route handler: answers 302 to the provider with the transaction cookie set. */
export function loginHandler(oidc: Oidc, options: LoginHandlerOptions = {}): RouteHandler {
  const onError = options.onError ?? defaultOnError;
  return async function login(req: Request): Promise<Response> {
    try {
      const next = new URL(req.url, 'http://request.invalid').searchParams.get('next');
      const { url, cookie } = await oidc.beginLogin({ next });
      return new Response(null, {
        status: 302,
        headers: { Location: url, 'Set-Cookie': cookie.header, 'Cache-Control': 'no-store' },
      });
    } catch (err) {
      return errorResponse(err, req, onError);
    }
  };
}

/** `GET /callback` route handler: verifies the login, calls `onLogin`, and clears the transaction cookie. */
export function callbackHandler(options: CallbackHandlerOptions): RouteHandler {
  const { oidc, onLogin } = options;
  const onError = options.onError ?? defaultOnError;
  return async function callback(req: Request): Promise<Response> {
    const clear = oidc.clearCookie().header;
    try {
      // Only the query string of req.url is used; origin and path come from the configured redirect URI.
      const currentUrl = new URL(req.url, oidc.redirectUri);
      const result = await oidc.completeLogin(currentUrl, readCookie(req.headers.get('cookie'), oidc.cookieName));
      const response = await onLogin(result.claims, { req, next: result.next, idToken: result.idToken });
      if (!isResponse(response)) throw new TypeError('callbackHandler: onLogin must return a Response');
      return withSetCookie(response, clear);
    } catch (err) {
      return errorResponse(err, req, onError, clear);
    }
  };
}
