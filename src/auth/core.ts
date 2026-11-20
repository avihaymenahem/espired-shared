// @espired/shared/auth — framework-neutral OIDC login helpers.
//
// Does the OIDC handshake only: authorization code flow with PKCE (S256), state and nonce,
// carried in a sealed, short-lived transaction cookie, plus safe post-login redirects.
// Apps keep their own account linking, sessions, CSRF protection and API tokens.

import { timingSafeEqual } from 'node:crypto';
import * as client from 'openid-client';
import { isValidCookieName, makeCookie, readCookie, type CookieOptions, type TransactionCookie } from './cookies.js';
import { deriveKey, seal, unseal } from './seal.js';

export { readCookie };
export type { CookieOptions, TransactionCookie };

export interface OidcOptions {
  /** Exact issuer, e.g. `https://auth.example.com/application/o/my-app/` (keep authentik's trailing slash). */
  issuer: string;
  clientId: string;
  clientSecret: string;
  /** Absolute callback URL registered with the provider. No query string or fragment. */
  redirectUri: string;
  /** Default `post_logout_redirect_uri` for `buildLogoutUrl()`. */
  postLogoutRedirectUri?: string;
  /** Defaults to `['openid', 'profile', 'email']`. Must include `openid`. */
  scopes?: string[];
  /** At least 32 characters. Used to derive the AES-256-GCM key for the transaction cookie. */
  cookieSecret: string;
  /** Defaults to `oidc_tx`. */
  cookieName?: string;
  /** Lifetime of a login attempt in seconds. Defaults to 600 (10 minutes). */
  transactionTtlSec?: number;
  /** Adds `Secure` to the transaction cookie. Defaults to true; turn off only for plain-http local dev. */
  secureCookies?: boolean;
  /** Allows an `http://` issuer. For local development and tests only. Defaults to false. */
  allowInsecureRequests?: boolean;
}

export interface OidcClaims {
  iss: string;
  sub: string;
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  /** Group names from the `groups` claim; empty when the provider sent none. */
  groups: string[];
}

export interface BeginLoginOptions {
  /** Where to send the user after login. Only same-origin relative paths are kept (see `safeNext`). */
  next?: string | null;
}

export interface BeginLoginResult {
  /** The provider's authorization URL. Redirect the browser here. */
  url: string;
  /** Set this cookie on the redirect response. */
  cookie: TransactionCookie;
}

export interface CompleteLoginResult {
  claims: OidcClaims;
  /** The raw ID token. Keep it if you want to pass it as `idTokenHint` on logout. */
  idToken: string;
  /** The safe `next` path captured by `beginLogin()`. */
  next: string;
}

export interface LogoutUrlOptions {
  idTokenHint?: string;
  /** Overrides the `postLogoutRedirectUri` given to `createOidc()`. */
  postLogoutRedirectUri?: string;
}

export interface Oidc {
  readonly cookieName: string;
  readonly redirectUri: string;
  beginLogin(options?: BeginLoginOptions): Promise<BeginLoginResult>;
  /**
   * Validates the callback and exchanges the code. Only the query string of `currentUrl` is
   * used; origin and path always come from `redirectUri`, never from the request's Host.
   */
  completeLogin(currentUrl: URL, sealedCookie: string | null | undefined): Promise<CompleteLoginResult>;
  /** A cookie that deletes the transaction cookie. */
  clearCookie(): TransactionCookie;
  /**
   * The provider's RP-initiated logout URL, or undefined when the provider has no
   * end-session endpoint or cannot be reached (so local logout never fails because of it).
   */
  buildLogoutUrl(options?: LogoutUrlOptions): Promise<string | undefined>;
}

export type OidcErrorCode =
  /** The transaction cookie is missing, malformed, or was tampered with. */
  | 'invalid_transaction'
  /** The transaction cookie is older than `transactionTtlSec`. */
  | 'expired_transaction'
  /** The callback's `state` does not match the transaction. */
  | 'state_mismatch'
  /** The provider returned an error, or the code exchange / ID token validation failed. */
  | 'provider_error'
  /** The provider's discovery document could not be loaded. */
  | 'discovery_failed';

export class OidcError extends Error {
  readonly code: OidcErrorCode;
  constructor(code: OidcErrorCode, message: string, options?: { cause?: unknown }) {
    super(message, options);
    this.name = 'OidcError';
    this.code = code;
  }
}

/** Throw this from your `onLogin` callback to answer 403 (e.g. the user is not in `admins`). */
export class OidcAccessDenied extends Error {
  readonly status = 403;
  constructor(message = 'Access denied.') {
    super(message);
    this.name = 'OidcAccessDenied';
  }
}

const MAX_NEXT_LENGTH = 2048;
const NEXT_BASE = 'http://safe-next.invalid';
// eslint-disable-next-line no-control-regex
const UNSAFE_NEXT_CHARS = /[\u0000-\u001f\u007f\\]/;

/**
 * Returns `value` if it is a same-origin relative path (`/...`), otherwise `fallback`.
 * Rejects `//host`, `/\host`, absolute URLs and schemes, backslashes and control characters.
 * The result is normalized (dot segments resolved, non-ASCII percent-encoded) and safe to put
 * in a `Location` header.
 */
export function safeNext(value: unknown, fallback = '/'): string {
  if (typeof value !== 'string') return fallback;
  if (value.length === 0 || value.length > MAX_NEXT_LENGTH) return fallback;
  if (value[0] !== '/' || value[1] === '/' || value[1] === '\\') return fallback;
  if (UNSAFE_NEXT_CHARS.test(value)) return fallback;
  let parsed: URL;
  try {
    parsed = new URL(value, NEXT_BASE);
  } catch {
    return fallback;
  }
  if (parsed.origin !== NEXT_BASE || parsed.pathname.startsWith('//')) return fallback;
  return `${parsed.pathname}${parsed.search}${parsed.hash}`;
}

/** True when the claims' `groups` contains `group` exactly. */
export function hasGroup(claims: Pick<OidcClaims, 'groups'> | null | undefined, group: string): boolean {
  return Array.isArray(claims?.groups) && claims.groups.includes(group);
}

interface Transaction {
  state: string;
  nonce: string;
  verifier: string;
  next: string;
  /** Expiry, milliseconds since the epoch. */
  exp: number;
}

function parseTransaction(value: unknown): Transaction | undefined {
  if (typeof value !== 'object' || value === null) return undefined;
  const t = value as Record<string, unknown>;
  if (
    typeof t.state !== 'string' ||
    typeof t.nonce !== 'string' ||
    typeof t.verifier !== 'string' ||
    typeof t.next !== 'string' ||
    typeof t.exp !== 'number'
  ) {
    return undefined;
  }
  return { state: t.state, nonce: t.nonce, verifier: t.verifier, next: t.next, exp: t.exp };
}

function constantTimeEqual(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  return left.length === right.length && timingSafeEqual(left, right);
}

function toClaims(idClaims: client.IDToken): OidcClaims {
  const groups = Array.isArray(idClaims.groups)
    ? idClaims.groups.filter((group): group is string => typeof group === 'string')
    : [];
  const claims: OidcClaims = { iss: idClaims.iss, sub: idClaims.sub, groups };
  if (typeof idClaims.email === 'string') claims.email = idClaims.email;
  if (typeof idClaims.email_verified === 'boolean') claims.email_verified = idClaims.email_verified;
  if (typeof idClaims.name === 'string') claims.name = idClaims.name;
  if (typeof idClaims.preferred_username === 'string') claims.preferred_username = idClaims.preferred_username;
  return claims;
}

function requireString(name: string, value: unknown): string {
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`createOidc: "${name}" is required`);
  }
  return value;
}

function requireUrl(name: string, value: unknown): URL {
  const text = requireString(name, value);
  let url: URL;
  try {
    url = new URL(text);
  } catch {
    throw new TypeError(`createOidc: "${name}" must be an absolute URL`);
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    throw new TypeError(`createOidc: "${name}" must be an http(s) URL`);
  }
  return url;
}

export function createOidc(options: OidcOptions): Oidc {
  const issuer = requireUrl('issuer', options.issuer);
  const clientId = requireString('clientId', options.clientId);
  const clientSecret = requireString('clientSecret', options.clientSecret);
  const redirectUri = requireUrl('redirectUri', options.redirectUri);
  if (redirectUri.search || redirectUri.hash) {
    throw new TypeError('createOidc: "redirectUri" must not contain a query string or fragment');
  }
  const defaultPostLogout =
    options.postLogoutRedirectUri === undefined
      ? undefined
      : requireUrl('postLogoutRedirectUri', options.postLogoutRedirectUri).href;
  if (typeof options.cookieSecret !== 'string' || options.cookieSecret.length < 32) {
    throw new TypeError('createOidc: "cookieSecret" must be at least 32 characters');
  }
  const cookieName = options.cookieName ?? 'oidc_tx';
  if (!isValidCookieName(cookieName)) {
    throw new TypeError('createOidc: "cookieName" is not a valid cookie name');
  }
  const ttl = options.transactionTtlSec ?? 600;
  if (!Number.isInteger(ttl) || ttl < 1 || ttl > 3600) {
    throw new TypeError('createOidc: "transactionTtlSec" must be an integer between 1 and 3600');
  }
  const scopes = options.scopes ?? ['openid', 'profile', 'email'];
  if (!scopes.includes('openid')) {
    throw new TypeError('createOidc: "scopes" must include "openid"');
  }
  const secure = options.secureCookies ?? true;
  const allowInsecure = options.allowInsecureRequests ?? false;
  const key = deriveKey(options.cookieSecret);

  let configPromise: Promise<client.Configuration> | undefined;
  function getConfig(): Promise<client.Configuration> {
    configPromise ??= client
      .discovery(
        issuer,
        clientId,
        clientSecret,
        client.ClientSecretBasic(clientSecret),
        allowInsecure ? { execute: [client.allowInsecureRequests] } : undefined,
      )
      .catch((cause: unknown) => {
        configPromise = undefined; // never cache a failed discovery
        throw new OidcError('discovery_failed', 'OIDC discovery failed', { cause });
      });
    return configPromise;
  }

  function cookieOptions(maxAge: number): CookieOptions {
    return { httpOnly: true, sameSite: 'lax', path: '/', secure, maxAge };
  }

  return {
    cookieName,
    redirectUri: redirectUri.href,

    async beginLogin({ next } = {}) {
      const config = await getConfig();
      const verifier = client.randomPKCECodeVerifier();
      const challenge = await client.calculatePKCECodeChallenge(verifier);
      const state = client.randomState();
      const nonce = client.randomNonce();
      const url = client.buildAuthorizationUrl(config, {
        redirect_uri: redirectUri.href,
        scope: scopes.join(' '),
        code_challenge: challenge,
        code_challenge_method: 'S256',
        state,
        nonce,
      });
      const transaction: Transaction = { state, nonce, verifier, next: safeNext(next), exp: Date.now() + ttl * 1000 };
      return { url: url.href, cookie: makeCookie(cookieName, seal(key, cookieName, transaction), cookieOptions(ttl)) };
    },

    async completeLogin(currentUrl, sealedCookie) {
      if (!(currentUrl instanceof URL)) throw new TypeError('completeLogin: "currentUrl" must be a URL');
      if (!sealedCookie) throw new OidcError('invalid_transaction', 'Missing login transaction cookie');
      const transaction = parseTransaction(unseal(key, cookieName, sealedCookie));
      if (!transaction) throw new OidcError('invalid_transaction', 'Invalid login transaction cookie');
      if (Date.now() >= transaction.exp) throw new OidcError('expired_transaction', 'Login transaction expired');

      const params = currentUrl.searchParams;
      const state = params.get('state');
      if (state === null || !constantTimeEqual(state, transaction.state)) {
        throw new OidcError('state_mismatch', 'Login state mismatch');
      }
      const providerError = params.get('error');
      if (providerError !== null) {
        const code = /^[\w.-]{1,64}$/.test(providerError) ? providerError : 'unknown';
        throw new OidcError('provider_error', `Identity provider returned an error: ${code}`);
      }

      // Origin and path come from the configured redirect URI; only the query is taken from the request.
      const callbackUrl = new URL(redirectUri.href);
      for (const [name, value] of params) callbackUrl.searchParams.append(name, value);

      const config = await getConfig();
      let tokens: Awaited<ReturnType<typeof client.authorizationCodeGrant>>;
      try {
        tokens = await client.authorizationCodeGrant(config, callbackUrl, {
          pkceCodeVerifier: transaction.verifier,
          expectedState: transaction.state,
          expectedNonce: transaction.nonce,
          idTokenExpected: true,
        });
      } catch (cause) {
        throw new OidcError('provider_error', 'Authorization code exchange failed', { cause });
      }
      const idClaims = tokens.claims();
      const idToken = tokens.id_token;
      if (!idClaims || !idToken) throw new OidcError('provider_error', 'The provider returned no ID token');
      return { claims: toClaims(idClaims), idToken, next: safeNext(transaction.next) };
    },

    clearCookie() {
      return makeCookie(cookieName, '', cookieOptions(0));
    },

    async buildLogoutUrl({ idTokenHint, postLogoutRedirectUri } = {}) {
      let config: client.Configuration;
      try {
        config = await getConfig();
      } catch {
        return undefined;
      }
      if (!config.serverMetadata().end_session_endpoint) return undefined;
      const params: Record<string, string> = {};
      if (idTokenHint) params.id_token_hint = idTokenHint;
      const postLogout = postLogoutRedirectUri ?? defaultPostLogout;
      if (postLogout) params.post_logout_redirect_uri = postLogout;
      return client.buildEndSessionUrl(config, params).href;
    },
  };
}
