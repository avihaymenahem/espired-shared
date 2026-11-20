/**
 * Cookie attributes in a framework-neutral shape.
 * `maxAge` is in SECONDS (the Next.js / `cookie` package convention). Express's
 * `res.cookie()` expects milliseconds, so with Express prefer the ready-made `header`.
 */
export interface CookieOptions {
    httpOnly: true;
    sameSite: 'lax';
    path: '/';
    secure: boolean;
    maxAge: number;
}
export interface TransactionCookie {
    name: string;
    value: string;
    options: CookieOptions;
    /** The complete `Set-Cookie` header value. */
    header: string;
}
export declare function isValidCookieName(name: string): boolean;
export declare function makeCookie(name: string, value: string, options: CookieOptions): TransactionCookie;
/**
 * Reads one cookie from a `Cookie` request header. Returns the first match, or undefined.
 * Works with `req.headers.cookie` (Node/Express) and `request.headers.get('cookie')` (Web).
 */
export declare function readCookie(header: string | null | undefined, name: string): string | undefined;
