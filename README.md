# @espired/shared

Small shared helpers for Espired apps. Right now that means **OIDC login** against a
self-hosted identity provider such as authentik:

- authorization code flow with **PKCE (S256)**, **state** and **nonce**;
- a sealed (AES-256-GCM), short-lived, HttpOnly transaction cookie, so the server stores nothing;
- safe post-login redirects (`next`), only same-origin relative paths;
- adapters for **Express** and the **Next.js App Router**.

It only does the handshake. Each app keeps its own account linking (match on `iss` + `sub`
inside `onLogin`), sessions, CSRF protection and API tokens.

## Install

The package is installed straight from git. `dist/` is committed, so there is no build step
and no install scripts.

```sh
npm i github:avihaymenahem/espired-shared#v0.1.0
pnpm add github:avihaymenahem/espired-shared#v0.1.0
```

In Docker images without `git` (e.g. `node:24-alpine`, `node:24-*-slim`), use the tag's tarball:

```sh
npm i https://codeload.github.com/avihaymenahem/espired-shared/tar.gz/refs/tags/v0.1.0
```

Requires Node.js 20.19 or newer. ESM only.

## Configuration

| Env var              | Example                                              |
| -------------------- | ---------------------------------------------------- |
| `OIDC_ISSUER`        | `https://auth.example.com/application/o/my-app/`     |
| `OIDC_CLIENT_ID`     | from the authentik provider                          |
| `OIDC_CLIENT_SECRET` | from the authentik provider                          |

You also need a cookie secret of at least 32 characters (e.g. `openssl rand -base64 48`)
for the transaction cookie. It can be your app's existing session secret.

In authentik, create an **OAuth2/OpenID provider** (confidential client) and an application:

- **Issuer:** copy it exactly, including the trailing `/`. Discovery fails if it differs.
- **Redirect URI:** the app's callback, e.g. `https://app.example.com/auth/oidc/callback`.
- **Scopes:** `openid profile email` (the default). authentik's `profile` mapping sends `groups`.
- Keep **"Include claims in id_token"** on (the default). Claims are read from the ID token.
- Bind the application to the group(s) allowed in, and check the group again in `onLogin`.

## Express

```ts
import express from 'express';
import { createOidc, hasGroup, OidcAccessDenied } from '@espired/shared/auth';
import { oidcRouter } from '@espired/shared/auth/express';

const oidc = createOidc({
  issuer: process.env.OIDC_ISSUER!,
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET!,
  redirectUri: 'https://app.example.com/auth/oidc/callback',
  postLogoutRedirectUri: 'https://app.example.com/',
  cookieSecret: process.env.SESSION_SECRET!,
});

const app = express();
app.use(
  '/auth/oidc', // serves GET /auth/oidc/login?next=/path and GET /auth/oidc/callback
  oidcRouter({
    oidc,
    async onLogin(claims, req, res, { next, idToken }) {
      if (!hasGroup(claims, 'admins')) throw new OidcAccessDenied(); // -> 403
      const user = await findOrLinkUser(claims.iss, claims.sub);    // your code
      await startSession(req, res, user.id);                         // your code
      // return { redirect: '/somewhere' } to override; default is the safe `next`
    },
  }),
);
```

The router is plain middleware (`express` is only a type dependency). Errors answer `400`
(missing/expired/tampered transaction, wrong state), `401` (provider error, replayed code),
`403` (`OidcAccessDenied`), `502` (provider unreachable) or `500`, with a short plain-text
body and no stack. Pass `onError(err, req)` to log them; by default only 5xx are logged.
If `onLogin` throws, cookies it already set on `res` are dropped.

## Next.js (App Router)

```ts
// src/lib/oidc.ts
import { createOidc } from '@espired/shared/auth';

export const oidc = createOidc({
  issuer: process.env.OIDC_ISSUER!,
  clientId: process.env.OIDC_CLIENT_ID!,
  clientSecret: process.env.OIDC_CLIENT_SECRET!,
  redirectUri: 'https://app.example.com/api/auth/callback',
  cookieSecret: process.env.SESSION_SECRET!,
});
```

```ts
// src/app/api/auth/login/route.ts
import { loginHandler } from '@espired/shared/auth/next';
import { oidc } from '@/lib/oidc';

export const GET = loginHandler(oidc); // 302 to the provider, sets the transaction cookie
```

```ts
// src/app/api/auth/callback/route.ts
import { NextResponse } from 'next/server';
import { hasGroup, OidcAccessDenied } from '@espired/shared/auth';
import { callbackHandler } from '@espired/shared/auth/next';
import { oidc } from '@/lib/oidc';

export const GET = callbackHandler({
  oidc,
  async onLogin(claims, { next }) {
    if (!hasGroup(claims, 'admins')) throw new OidcAccessDenied();
    await linkOwner(claims.iss, claims.sub);                      // your code
    const res = NextResponse.redirect(new URL(next, 'https://app.example.com'));
    await startSession(res);                                     // your code: sets the session cookie
    return res; // the handler appends the Set-Cookie that clears the transaction cookie
  },
});
```

The adapter only uses the Web `Request`/`Response` types and never imports `next`. Use the
Node.js runtime (the default for route handlers).

## Logout

```ts
const url = await oidc.buildLogoutUrl({ idTokenHint }); // undefined if there is no end-session endpoint
```

End your own session first, then send the browser to `url` when it is defined. Keep the
`idToken` from `onLogin` in your session if you want to pass it as `idTokenHint`.

## API

### `@espired/shared/auth`

```ts
createOidc(options: OidcOptions): Oidc

interface OidcOptions {
  issuer: string;                  // exact issuer URL
  clientId: string;
  clientSecret: string;
  redirectUri: string;             // absolute, no query or fragment
  postLogoutRedirectUri?: string;
  scopes?: string[];               // default ['openid', 'profile', 'email']
  cookieSecret: string;            // >= 32 chars
  cookieName?: string;             // default 'oidc_tx'
  transactionTtlSec?: number;      // default 600
  secureCookies?: boolean;         // default true
  allowInsecureRequests?: boolean; // default false; http:// issuer for local dev/tests only
}

interface Oidc {
  readonly cookieName: string;
  readonly redirectUri: string;
  beginLogin(options?: { next?: string | null }): Promise<{ url: string; cookie: TransactionCookie }>;
  completeLogin(currentUrl: URL, sealedCookie: string | null | undefined):
    Promise<{ claims: OidcClaims; idToken: string; next: string }>;
  clearCookie(): TransactionCookie;
  buildLogoutUrl(options?: { idTokenHint?: string; postLogoutRedirectUri?: string }): Promise<string | undefined>;
}

interface OidcClaims {
  iss: string; sub: string;
  email?: string; email_verified?: boolean;
  name?: string; preferred_username?: string;
  groups: string[]; // [] when the provider sent none
}

interface TransactionCookie {
  name: string; value: string;
  options: { httpOnly: true; sameSite: 'lax'; path: '/'; secure: boolean; maxAge: number /* seconds */ };
  header: string; // full Set-Cookie value
}

hasGroup(claims, group: string): boolean
safeNext(value: unknown, fallback = '/'): string
readCookie(cookieHeader: string | null | undefined, name: string): string | undefined
class OidcError extends Error { code: 'invalid_transaction' | 'expired_transaction' | 'state_mismatch' | 'provider_error' | 'discovery_failed' }
class OidcAccessDenied extends Error { status: 403 }
```

`completeLogin` uses only the query string of `currentUrl`; the origin and path always come
from `redirectUri`, so a spoofed `Host` header or an internal proxy address cannot change the
token request. Discovery runs on first use and is cached; a failed discovery is retried next time.

### `@espired/shared/auth/express`

```ts
oidcRouter(options: {
  oidc: Oidc;
  onLogin(claims: OidcClaims, req: Request, res: Response, ctx: { next: string; idToken: string }):
    { redirect?: string } | void | Promise<{ redirect?: string } | void>;
  onError?(err: unknown, req: Request): void;
}): RequestHandler
```

### `@espired/shared/auth/next`

```ts
loginHandler(oidc: Oidc, options?: { onError?(err: unknown, req: Request): void }): (req: Request) => Promise<Response>
callbackHandler(options: {
  oidc: Oidc;
  onLogin(claims: OidcClaims, ctx: { req: Request; next: string; idToken: string }): Response | Promise<Response>;
  onError?(err: unknown, req: Request): void;
}): (req: Request) => Promise<Response>
```

## Development

```sh
npm install
npm test          # node:test + tsx against an in-process oidc-provider
npm run typecheck
npm run build     # writes dist/ — commit it
```

Release: bump `version`, `npm run build`, commit (including `dist/`), tag `vX.Y.Z`, push the tag.
