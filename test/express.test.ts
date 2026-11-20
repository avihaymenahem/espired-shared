import assert from 'node:assert/strict';
import { after, before, beforeEach, describe, test } from 'node:test';
import express from 'express';
import { createOidc, hasGroup, OidcAccessDenied, type OidcClaims } from '../src/auth/core.js';
import { oidcRouter, type ExpressLoginContext, type OnLoginResult } from '../src/auth/express.js';
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
let logins: Array<{ claims: OidcClaims; ctx: ExpressLoginContext }>;
let onLoginResult: OnLoginResult | undefined;
let errors: unknown[];

before(async () => {
  h = await startHarness();
  const oidc = createOidc({
    issuer: h.issuer,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri: `${h.appOrigin}/auth/oidc/callback`,
    cookieSecret: COOKIE_SECRET,
    secureCookies: false,
    allowInsecureRequests: true,
  });
  const app = express();
  app.use(
    '/auth/oidc',
    oidcRouter({
      oidc,
      async onLogin(claims, _req, res, ctx) {
        // The app sets its own session cookie, then requires admins. If it throws after
        // setting the cookie, the router must drop that cookie.
        res.cookie('app_session', 'session-123', { httpOnly: true, path: '/' });
        if (!hasGroup(claims, 'admins')) throw new OidcAccessDenied();
        logins.push({ claims, ctx });
        return onLoginResult;
      },
      onError(err) {
        errors.push(err);
      },
    }),
  );
  app.get('/after', (_req, res) => {
    res.send('fallthrough ok');
  });
  h.setAppHandler(app);
});
after(async () => {
  await h.close();
});
beforeEach(() => {
  logins = [];
  errors = [];
  onLoginResult = undefined;
  h.idp.account = 'user-admin';
});

async function startLogin(next?: string): Promise<{ callbackUrl: URL; txCookie: string; loginRes: Response }> {
  const query = next === undefined ? '' : `?next=${encodeURIComponent(next)}`;
  const loginRes = await fetch(`${h.appOrigin}/auth/oidc/login${query}`, { redirect: 'manual' });
  assert.equal(loginRes.status, 302);
  const location = loginRes.headers.get('location')!;
  const callbackUrl = await authorize(location, `${h.appOrigin}/auth/oidc/callback`);
  return { callbackUrl, txCookie: cookieValue(loginRes.headers, 'oidc_tx'), loginRes };
}

function callback(url: URL, txCookie?: string): Promise<Response> {
  return fetch(url, { redirect: 'manual', headers: txCookie ? { cookie: `other=1; oidc_tx=${txCookie}` } : {} });
}

describe('oidcRouter (Express)', () => {
  test('full round trip: login, IdP, callback, onLogin, redirect to next', async () => {
    const { callbackUrl, txCookie, loginRes } = await startLogin('/docs/42?tab=notes');
    assert.ok(loginRes.headers.get('location')!.startsWith(h.issuer));
    assert.equal(loginRes.headers.get('cache-control'), 'no-store');
    const txHeader = setCookieFor(loginRes.headers, 'oidc_tx')!;
    assert.match(txHeader, /; Path=\/; Max-Age=600; HttpOnly; SameSite=Lax$/);

    const res = await callback(callbackUrl, txCookie);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/docs/42?tab=notes');
    assert.match(setCookieFor(res.headers, 'oidc_tx')!, /^oidc_tx=; Path=\/; Max-Age=0/);
    assert.match(setCookieFor(res.headers, 'app_session')!, /^app_session=session-123/);

    assert.equal(logins.length, 1);
    const { claims, ctx } = logins[0]!;
    assert.equal(claims.iss, h.issuer);
    assert.equal(claims.sub, 'user-admin');
    assert.equal(claims.email, 'owner@example.com');
    assert.deepEqual(claims.groups, ['admins', 'family']);
    assert.equal(ctx.next, '/docs/42?tab=notes');
    assert.equal(ctx.idToken.split('.').length, 3);
    assert.deepEqual(errors, []);
  });

  test('onLogin can choose the redirect', async () => {
    onLoginResult = { redirect: '/welcome' };
    const { callbackUrl, txCookie } = await startLogin('/docs');
    const res = await callback(callbackUrl, txCookie);
    assert.equal(res.status, 302);
    assert.equal(res.headers.get('location'), '/welcome');
  });

  test('unsafe next falls back to /', async () => {
    const { callbackUrl, txCookie } = await startLogin('//evil.example.com/x');
    const res = await callback(callbackUrl, txCookie);
    assert.equal(res.headers.get('location'), '/');
  });

  test('missing cookie answers 400 without a stack', async () => {
    const { callbackUrl } = await startLogin();
    const res = await callback(callbackUrl);
    assert.equal(res.status, 400);
    assert.match(res.headers.get('content-type')!, /^text\/plain/);
    const body = await res.text();
    assert.equal(body, 'Login expired or invalid. Please start the login again.');
    assert.match(setCookieFor(res.headers, 'oidc_tx')!, /Max-Age=0/);
    assert.equal(logins.length, 0);
    assert.equal(errors.length, 1);
  });

  test('tampered cookie answers 400', async () => {
    const { callbackUrl, txCookie } = await startLogin();
    const res = await callback(callbackUrl, `${txCookie.slice(0, 20)}${txCookie[20] === 'A' ? 'B' : 'A'}${txCookie.slice(21)}`);
    assert.equal(res.status, 400);
  });

  test('wrong state answers 400', async () => {
    const { callbackUrl, txCookie } = await startLogin();
    callbackUrl.searchParams.set('state', 'nope');
    const res = await callback(callbackUrl, txCookie);
    assert.equal(res.status, 400);
  });

  test('replayed code answers 401', async () => {
    const { callbackUrl, txCookie } = await startLogin();
    assert.equal((await callback(callbackUrl, txCookie)).status, 302);
    const replay = await callback(callbackUrl, txCookie);
    assert.equal(replay.status, 401);
    assert.equal(await replay.text(), 'Login failed.');
    assert.equal(logins.length, 1);
  });

  test('OidcAccessDenied from onLogin answers 403 and drops the app cookie', async () => {
    h.idp.account = 'user-plain';
    const { callbackUrl, txCookie } = await startLogin();
    const res = await callback(callbackUrl, txCookie);
    assert.equal(res.status, 403);
    assert.equal(await res.text(), 'Access denied.');
    assert.equal(setCookieFor(res.headers, 'app_session'), undefined);
    assert.match(setCookieFor(res.headers, 'oidc_tx')!, /Max-Age=0/);
  });

  test('other paths and methods fall through', async () => {
    const res = await fetch(`${h.appOrigin}/after`);
    assert.equal(await res.text(), 'fallthrough ok');
    const post = await fetch(`${h.appOrigin}/auth/oidc/login`, { method: 'POST', redirect: 'manual' });
    assert.equal(post.status, 404);
    const unknown = await fetch(`${h.appOrigin}/auth/oidc/other`, { redirect: 'manual' });
    assert.equal(unknown.status, 404);
  });
});
