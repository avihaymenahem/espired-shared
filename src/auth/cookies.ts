// Cookie helpers shared by the core and the framework adapters.

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

const TOKEN = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;

export function isValidCookieName(name: string): boolean {
  return TOKEN.test(name);
}

export function makeCookie(name: string, value: string, options: CookieOptions): TransactionCookie {
  const parts = [`${name}=${value}`, `Path=${options.path}`, `Max-Age=${options.maxAge}`];
  if (options.maxAge === 0) parts.push('Expires=Thu, 01 Jan 1970 00:00:00 GMT');
  parts.push('HttpOnly', 'SameSite=Lax');
  if (options.secure) parts.push('Secure');
  return { name, value, options, header: parts.join('; ') };
}

/**
 * Reads one cookie from a `Cookie` request header. Returns the first match, or undefined.
 * Works with `req.headers.cookie` (Node/Express) and `request.headers.get('cookie')` (Web).
 */
export function readCookie(header: string | null | undefined, name: string): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1 || part.slice(0, eq).trim() !== name) continue;
    let value = part.slice(eq + 1).trim();
    if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) value = value.slice(1, -1);
    try {
      return decodeURIComponent(value);
    } catch {
      return value;
    }
  }
  return undefined;
}
