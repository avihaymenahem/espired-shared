import { type Oidc, type OidcClaims } from './core.js';
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
/** `GET /login?next=` route handler: answers 302 to the provider with the transaction cookie set. */
export declare function loginHandler(oidc: Oidc, options?: LoginHandlerOptions): RouteHandler;
/** `GET /callback` route handler: verifies the login, calls `onLogin`, and clears the transaction cookie. */
export declare function callbackHandler(options: CallbackHandlerOptions): RouteHandler;
