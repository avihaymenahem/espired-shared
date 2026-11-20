import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, test } from 'node:test';
import { createOidc, hasGroup, OidcAccessDenied, type Oidc, type OidcClaims } from '../src/auth/core.js';
import { callbackHandler, loginHandler, type NextLoginContext } from '../src/auth/next.js';
import {
  authorize,
  CLIENT_ID,
  CLIENT_SECRET,
  COOKIE_SECRET,
  cookieValue,
  setCookieFor,
  startHarness,
  type Harness,
} from './support/harness.js';

let h: Harness;
let oidc: Oidc;
let redirectUri: string;
let logins: Array<{ claims: OidcClaims; ctx: NextLoginContext }>;

before(async () => {
  h = await startHarness();
  redirectUri = `${h.appOrigin}/api/auth/callback`;
  oidc = createOidc({
    issuer: h.issuer,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri,
    cookieSecret: COOKIE_SECRET,
    secureCookies: false,
    allowInsecureRequests: true,
  });
});
after(async () => {
  await h.close();
});
beforeEach(() => {
  logins = [];
  h.idp.account = 'user-admin';
});

const quiet = { onError: () => {} };

// What Portal will do: check the group, set its session cookie on the redirect it returns.
const GET_callback = () =>
  callbackHandler({
    oidc,
    ...quiet,
    async onLogin(claims, ctx) {
      if (!hasGroup(claims, 'admins')) throw new OidcAccessDenied();
      logins.push({ claims, ctx });
      const res = new Response(null, { status: 302, headers: { Location: new URL(ctx.next, 'https://portal.example.com').href } });
      res.headers.append('Set-Cookie', 'portal_session=abc; Path=/; HttpOnly; SameSite=Lax');
      return res;
    },
  });

async function startLogin(next?: string): Promise<{ callbackUrl: URL; txCookie: string; loginRes: Response }> {
  // Next passes an absolute req.url; its host is never trusted for the callback.
  const query = next === undefined ? '' : `?next=${encodeURIComponent(next)}`;
  const loginRes = await loginHandler(oidc, quiet)(new Request(`http://0.0.0.0:3000/api/auth/login${query}`));
  assert.equal(loginRes.status, 302);
  const callbackUrl = await authorize(loginRes.headers.get('location')!, redirectUri);
  return { callbackUrl, txCookie: cookieValue(loginRes.headers, 'oidc_tx'), loginRes };
}

function callbackRequest(url: URL, txCookie?: string): Request {
  // Simulate a proxy: the request arrives at an internal host, with the IdP's query string.
  return new Request(`http://0.0.0.0:3000/api/auth/callback${url.search}`, {
    headers: txCookie ? { cookie: `x=1; oidc_tx=${txCookie}` } : {},
  });
}

describe('Next.js handlers', () => {
  test('full round trip: loginHandler, IdP, callbackHandler, onLogin response', async () => {
    const { callbackUrl, txCookie, loginRes } = await startLogin('/apps?tab=all');
    assert.ok(loginRes.headers.get('location')!.startsWith(h.issuer));
    assert.equal(loginRes.headers.get('cache-control'), 'no-store');
    assert.match(setCookieFor(loginRes.headers, 'oidc_tx')!, /; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax$/);

    const res = await GET_callback()(callbackRequest(callbackUrl, txCookie));
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), 'https://portal.example.com/apps?tab=all');
    assert.match(setCookieFor(res.headers, 'portal_session')!, /^portal_session=abc/);
    assert.match(setCookieFor(res.headers, 'oidc_tx')!, /^oidc_tx=; Path=\/; Max-Age=0/);

    assert.equal(logins.length, 1);
    const { claims, ctx } = logins[0]!;
    assert.equal(claims.iss, h.issuer);
    assert.equal(claims.sub, 'user-admin');
    assert.deepEqual(claims.groups, ['admins', 'family']);
    assert.equal(ctx.next, '/apps?tab=all');
    assert.equal(ctx.idToken.split('.').length, 3);
    assert.ok(ctx.req instanceof Request);
  });

  test('an immutable Response.redirect still gets the clearing cookie', async () => {
    const handler = callbackHandler({
      oidc,
      ...quiet,
      onLogin: (_claims, ctx) => Response.redirect(new URL(ctx.next, 'https://portal.example.com'), 303),
    });
    const { callbackUrl, txCookie } = await startLogin('/x');
    const res = await handler(callbackRequest(callbackUrl, txCookie));
    assert.equal(res.status, 303);
    assert.equal(res.headers.get('location'), 'https://portal.example.com/x');
    assert.match(setCookieFor(res.headers, 'oidc_tx')!, /Max-Age=0/);
  });

  test('missing cookie answers 400', async () => {
    const { callbackUrl } = await startLogin();
    const res = await GET_callback()(callbackRequest(callbackUrl));
    assert.equal(res.status, 400);
    assert.equal(await res.text(), 'Login expired or invalid. Please start the login again.');
    assert.match(setCookieFor(res.headers, 'oidc_tx')!, /Max-Age=0/);
    assert.equal(logins.length, 0);
  });

  test('wrong state answers 400', async () => {
    const { callbackUrl, txCookie } = await startLogin();
    callbackUrl.searchParams.set('state', 'nope');
    const res = await GET_callback()(callbackRequest(callbackUrl, txCookie));
    assert.equal(res.status, 400);
  });

  test('replayed code answers 401', async () => {
    const { callbackUrl, txCookie } = await startLogin();
    const handler = GET_callback();
    assert.equal((await handler(callbackRequest(callbackUrl, txCookie))).status, 302);
    const replay = await handler(callbackRequest(callbackUrl, txCookie));
    assert.equal(replay.status, 401);
    assert.equal(logins.length, 1);
  });

  test('OidcAccessDenied answers 403 with no session cookie', async () => {
    h.idp.account = 'user-plain';
    const { callbackUrl, txCookie } = await startLogin();
    const res = await GET_callback()(callbackRequest(callbackUrl, txCookie));
    assert.equal(res.status, 403);
    assert.equal(await res.text(), 'Access denied.');
    assert.equal(setCookieFor(res.headers, 'portal_session'), undefined);
  });

  test('onLogin that returns a non-Response answers 500', async () => {
    const errors: unknown[] = [];
    const handler = callbackHandler({
      oidc,
      onError: (err) => errors.push(err),
      onLogin: () => undefined as unknown as Response,
    });
    const { callbackUrl, txCookie } = await startLogin();
    const res = await handler(callbackRequest(callbackUrl, txCookie));
    assert.equal(res.status, 500);
    assert.equal(await res.text(), 'Login failed.');
    assert.equal(errors.length, 1);
  });

  test('discovery failure answers 502', async () => {
    const down = createOidc({
      issuer: 'http://127.0.0.1:9/application/o/none/',
      clientId: CLIENT_ID,
      clientSecret: CLIENT_SECRET,
      redirectUri,
      cookieSecret: COOKIE_SECRET,
      allowInsecureRequests: true,
    });
    const res = await loginHandler(down, quiet)(new Request('http://0.0.0.0:3000/api/auth/login'));
    assert.equal(res.status, 502);
    assert.equal(await res.text(), 'Identity provider unavailable.');
  });
});
