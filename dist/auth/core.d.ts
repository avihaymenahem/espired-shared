import { readCookie, type CookieOptions, type TransactionCookie } from './cookies.js';
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
'invalid_transaction'
/** The transaction cookie is older than `transactionTtlSec`. */
 | 'expired_transaction'
/** The callback's `state` does not match the transaction. */
 | 'state_mismatch'
/** The provider returned an error, or the code exchange / ID token validation failed. */
 | 'provider_error'
/** The provider's discovery document could not be loaded. */
 | 'discovery_failed';
export declare class OidcError extends Error {
    readonly code: OidcErrorCode;
    constructor(code: OidcErrorCode, message: string, options?: {
        cause?: unknown;
    });
}
/** Throw this from your `onLogin` callback to answer 403 (e.g. the user is not in `admins`). */
export declare class OidcAccessDenied extends Error {
    readonly status = 403;
    constructor(message?: string);
}
/**
 * Returns `value` if it is a same-origin relative path (`/...`), otherwise `fallback`.
 * Rejects `//host`, `/\host`, absolute URLs and schemes, backslashes and control characters.
 * The result is normalized (dot segments resolved, non-ASCII percent-encoded) and safe to put
 * in a `Location` header.
 */
export declare function safeNext(value: unknown, fallback?: string): string;
/** True when the claims' `groups` contains `group` exactly. */
export declare function hasGroup(claims: Pick<OidcClaims, 'groups'> | null | undefined, group: string): boolean;
export declare function createOidc(options: OidcOptions): Oidc;
