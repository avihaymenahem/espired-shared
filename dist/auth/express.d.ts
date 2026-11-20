import type { Request, RequestHandler, Response } from 'express';
import { type Oidc, type OidcClaims } from './core.js';
export interface ExpressLoginContext {
    /** Safe same-origin path the user asked for (defaults to `/`). */
    next: string;
    /** Raw ID token, e.g. to keep for `buildLogoutUrl({ idTokenHint })`. */
    idToken: string;
}
export interface OnLoginResult {
    /** Where to redirect after login. Defaults to `ctx.next`. Not validated: you control it. */
    redirect?: string;
}
export interface OidcRouterOptions {
    oidc: Oidc;
    /**
     * Called after a verified login. Link the account and start your own session here
     * (e.g. set your session cookie on `res`). Throw `OidcAccessDenied` to answer 403.
     * If you send the response yourself, the router does nothing more.
     */
    onLogin(claims: OidcClaims, req: Request, res: Response, ctx: ExpressLoginContext): OnLoginResult | void | Promise<OnLoginResult | void>;
    /** Called for every failed login/callback. Defaults to logging 5xx errors with console.error. */
    onError?(err: unknown, req: Request): void;
}
/**
 * Returns middleware that serves `GET /login?next=` and `GET /callback` relative to where it is
 * mounted, e.g. `app.use('/auth/oidc', oidcRouter({ oidc, onLogin }))`. Other requests fall through.
 */
export declare function oidcRouter(options: OidcRouterOptions): RequestHandler;
