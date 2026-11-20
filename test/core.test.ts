import assert from 'node:assert/strict';
import { after, before, describe, test } from 'node:test';
import {
  createOidc,
  hasGroup,
  OidcError,
  readCookie,
  safeNext,
  type Oidc,
  type OidcErrorCode,
  type OidcOptions,
} from '../src/auth/core.js';
import { deriveKey, seal, unseal } from '../src/auth/seal.js';
import { authorize, CLIENT_ID, CLIENT_SECRET, COOKIE_SECRET, startHarness, type Harness } from './support/harness.js';

let h: Harness;
let redirectUri: string;

before(async () => {
  h = await startHarness();
  redirectUri = `${h.appOrigin}/auth/oidc/callback`;
});
after(async () => {
  await h.close();
});

function makeOidc(overrides: Partial<OidcOptions> = {}): Oidc {
  return createOidc({
    issuer: h.issuer,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
    redirectUri,
    postLogoutRedirectUri: `${h.appOrigin}/`,
    cookieSecret: COOKIE_SECRET,
    secureCookies: false,
    allowInsecureRequests: true,
    ...overrides,
  });
}

async function rejectsWith(promise: Promise<unknown>, code: OidcErrorCode): Promise<void> {
  await assert.rejects(promise, (err: unknown) => {
    assert.ok(err instanceof OidcError, `expected OidcError, got ${String(err)}`);
    assert.equal(err.code, code);
    return true;
  });
}

/** Runs beginLogin and the IdP leg; returns the callback URL and the sealed cookie value. */
async function startFlow(oidc: Oidc, next?: string): Promise<{ callbackUrl: URL; cookie: string }> {
  const { url, cookie } = await oidc.beginLogin({ next });
  const callbackUrl = await authorize(url, redirectUri);
  return { callbackUrl, cookie: cookie.value };
}

function reseal(sealed: string, change: (tx: Record<string, unknown>) => void): string {
  const key = deriveKey(COOKIE_SECRET);
  const tx = unseal(key, 'oidc_tx', sealed) as Record<string, unknown>;
  assert.ok(tx, 'fixture cookie should unseal');
  change(tx);
  return seal(key, 'oidc_tx', tx);
}

describe('createOidc', () => {
  test('rejects a short cookie secret', () => {
    assert.throws(() => makeOidc({ cookieSecret: 'too-short' }), /cookieSecret/);
  });
  test('rejects a redirect URI with a query string', () => {
    assert.throws(() => makeOidc({ redirectUri: `${redirectUri}?x=1` }), /redirectUri/);
  });
  test('rejects scopes without openid', () => {
    assert.throws(() => makeOidc({ scopes: ['profile'] }), /openid/);
  });
});

describe('beginLogin', () => {
  test('builds a PKCE S256 authorization URL and a sealed cookie', async () => {
    const oidc = makeOidc({ secureCookies: true });
    const { url, cookie } = await oidc.beginLogin({ next: '/docs/42' });
    const auth = new URL(url);
    assert.ok(url.startsWith(h.issuer), url);
    assert.equal(auth.searchParams.get('response_type'), 'code');
    assert.equal(auth.searchParams.get('client_id'), CLIENT_ID);
    assert.equal(auth.searchParams.get('redirect_uri'), redirectUri);
    assert.equal(auth.searchParams.get('scope'), 'openid profile email');
    assert.equal(auth.searchParams.get('code_challenge_method'), 'S256');
    assert.ok(auth.searchParams.get('code_challenge'));
    assert.ok(auth.searchParams.get('state'));
    assert.ok(auth.searchParams.get('nonce'));

    assert.equal(cookie.name, 'oidc_tx');
    assert.deepEqual(cookie.options, { httpOnly: true, sameSite: 'lax', path: '/', secure: true, maxAge: 600 });
    assert.equal(cookie.header, `oidc_tx=${cookie.value}; Path=/; Max-Age=600; HttpOnly; SameSite=Lax; Secure`);
    // The cookie is opaque: no state, nonce, verifier or next in clear text.
    assert.ok(!cookie.value.includes(auth.searchParams.get('state')!));
    assert.ok(!cookie.value.includes('docs'));
  });

  test('a failed discovery is not cached', async () => {
    const oidc = makeOidc();
    h.idp.failNextDiscovery = true;
    await rejectsWith(oidc.beginLogin(), 'discovery_failed');
    const { url } = await oidc.beginLogin();
    assert.ok(url.startsWith(h.issuer));
  });
});

describe('completeLogin', () => {
  test('full round trip returns verified claims, groups, ID token and next', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc, '/docs/42?tab=notes');
    const result = await oidc.completeLogin(callbackUrl, cookie);
    assert.deepEqual(result.claims, {
      iss: h.issuer,
      sub: 'user-admin',
      email: 'owner@example.com',
      email_verified: true,
      name: 'Test Owner',
      preferred_username: 'owner',
      groups: ['admins', 'family'],
    });
    assert.equal(result.next, '/docs/42?tab=notes');
    assert.equal(result.idToken.split('.').length, 3);
    assert.ok(hasGroup(result.claims, 'admins'));
  });

  test('missing groups claim becomes an empty list', async () => {
    h.idp.account = 'user-plain';
    try {
      const oidc = makeOidc();
      const { callbackUrl, cookie } = await startFlow(oidc);
      const result = await oidc.completeLogin(callbackUrl, cookie);
      assert.equal(result.claims.sub, 'user-plain');
      assert.deepEqual(result.claims.groups, []);
      assert.equal(result.claims.email_verified, false);
      assert.equal(hasGroup(result.claims, 'admins'), false);
      assert.equal(result.next, '/');
    } finally {
      h.idp.account = 'user-admin';
    }
  });

  test('uses only the query of currentUrl; origin and path come from redirectUri', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    const spoofed = new URL(`https://evil.example.com/somewhere/else${callbackUrl.search}`);
    const result = await oidc.completeLogin(spoofed, cookie);
    assert.equal(result.claims.sub, 'user-admin');
  });

  test('missing cookie', async () => {
    const oidc = makeOidc();
    const { callbackUrl } = await startFlow(oidc);
    await rejectsWith(oidc.completeLogin(callbackUrl, undefined), 'invalid_transaction');
    await rejectsWith(oidc.completeLogin(callbackUrl, ''), 'invalid_transaction');
  });

  test('tampered cookie', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    const i = 20; // well inside the base64url body, so every bit of the character is significant
    const tampered = cookie.slice(0, i) + (cookie[i] === 'A' ? 'B' : 'A') + cookie.slice(i + 1);
    await rejectsWith(oidc.completeLogin(callbackUrl, tampered), 'invalid_transaction');
    await rejectsWith(oidc.completeLogin(callbackUrl, 'v1.not-a-real-cookie'), 'invalid_transaction');
    await rejectsWith(oidc.completeLogin(callbackUrl, 'garbage'), 'invalid_transaction');
  });

  test('cookie sealed with another secret or cookie name', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    const otherSecret = makeOidc({ cookieSecret: 'another-cookie-secret-0123456789-abcdefghij' });
    await rejectsWith(otherSecret.completeLogin(callbackUrl, cookie), 'invalid_transaction');
    const otherName = makeOidc({ cookieName: 'other_tx' });
    await rejectsWith(otherName.completeLogin(callbackUrl, cookie), 'invalid_transaction');
  });

  test('wrong state', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    const wrong = new URL(callbackUrl);
    wrong.searchParams.set('state', 'attacker-chosen-state');
    await rejectsWith(oidc.completeLogin(wrong, cookie), 'state_mismatch');
    const missing = new URL(callbackUrl);
    missing.searchParams.delete('state');
    await rejectsWith(oidc.completeLogin(missing, cookie), 'state_mismatch');
  });

  test('state from a different login attempt', async () => {
    const oidc = makeOidc();
    const first = await startFlow(oidc);
    const second = await startFlow(oidc);
    await rejectsWith(oidc.completeLogin(first.callbackUrl, second.cookie), 'state_mismatch');
  });

  test('expired transaction', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    const expired = reseal(cookie, (tx) => {
      tx.exp = Date.now() - 1000;
    });
    await rejectsWith(oidc.completeLogin(callbackUrl, expired), 'expired_transaction');
  });

  test('expired transaction with a real 1-second TTL', async () => {
    const oidc = makeOidc({ transactionTtlSec: 1 });
    const { callbackUrl, cookie } = await startFlow(oidc);
    await new Promise((resolve) => setTimeout(resolve, 1100));
    await rejectsWith(oidc.completeLogin(callbackUrl, cookie), 'expired_transaction');
  });

  test('wrong nonce is rejected by ID token validation', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    const wrongNonce = reseal(cookie, (tx) => {
      tx.nonce = 'some-other-nonce';
    });
    await rejectsWith(oidc.completeLogin(callbackUrl, wrongNonce), 'provider_error');
  });

  test('wrong PKCE verifier is rejected by the provider', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    const wrongVerifier = reseal(cookie, (tx) => {
      tx.verifier = 'x'.repeat(43);
    });
    await rejectsWith(oidc.completeLogin(callbackUrl, wrongVerifier), 'provider_error');
  });

  test('replayed code', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    await oidc.completeLogin(callbackUrl, cookie);
    await rejectsWith(oidc.completeLogin(callbackUrl, cookie), 'provider_error');
  });

  test('provider error response', async () => {
    const oidc = makeOidc();
    const { url, cookie } = await oidc.beginLogin();
    const state = new URL(url).searchParams.get('state')!;
    const errorUrl = new URL(redirectUri);
    errorUrl.searchParams.set('error', 'access_denied');
    errorUrl.searchParams.set('state', state);
    await rejectsWith(oidc.completeLogin(errorUrl, cookie.value), 'provider_error');
  });

  test('a tampered next inside a valid cookie is still made safe', async () => {
    const oidc = makeOidc();
    const { callbackUrl, cookie } = await startFlow(oidc);
    const evil = reseal(cookie, (tx) => {
      tx.next = '//evil.example.com';
    });
    const result = await oidc.completeLogin(callbackUrl, evil);
    assert.equal(result.next, '/');
  });
});

describe('clearCookie and buildLogoutUrl', () => {
  test('clearCookie expires the transaction cookie', () => {
    const cleared = makeOidc().clearCookie();
    assert.equal(cleared.name, 'oidc_tx');
    assert.equal(cleared.value, '');
    assert.equal(cleared.options.maxAge, 0);
    assert.equal(cleared.header, 'oidc_tx=; Path=/; Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT; HttpOnly; SameSite=Lax');
  });

  test('buildLogoutUrl points at the end-session endpoint', async () => {
    const oidc = makeOidc();
    const url = new URL((await oidc.buildLogoutUrl({ idTokenHint: 'the-id-token' }))!);
    assert.ok(url.href.startsWith(h.issuer), url.href);
    assert.equal(url.searchParams.get('id_token_hint'), 'the-id-token');
    assert.equal(url.searchParams.get('post_logout_redirect_uri'), `${h.appOrigin}/`);
    assert.equal(url.searchParams.get('client_id'), CLIENT_ID);

    const override = new URL((await oidc.buildLogoutUrl({ postLogoutRedirectUri: `${h.appOrigin}/bye` }))!);
    assert.equal(override.searchParams.get('post_logout_redirect_uri'), `${h.appOrigin}/bye`);
    assert.equal(override.searchParams.has('id_token_hint'), false);
  });

  test('buildLogoutUrl returns undefined when the provider is unreachable', async () => {
    const oidc = makeOidc({ issuer: 'http://127.0.0.1:9/application/o/none/' });
    assert.equal(await oidc.buildLogoutUrl(), undefined);
  });
});

describe('safeNext', () => {
  const kept: Array<[string, string]> = [
    ['/', '/'],
    ['/docs', '/docs'],
    ['/docs/42?tab=notes#top', '/docs/42?tab=notes#top'],
    ['/a/b/../c', '/a/c'],
    ['/%2F%2Fevil.example.com', '/%2F%2Fevil.example.com'],
    ['/javascript:alert(1)', '/javascript:alert(1)'],
    ['/search?q=a b', '/search?q=a%20b'],
    ['/מסמכים', '/%D7%9E%D7%A1%D7%9E%D7%9B%D7%99%D7%9D'],
  ];
  for (const [input, expected] of kept) {
    test(`keeps ${JSON.stringify(input)}`, () => {
      assert.equal(safeNext(input), expected);
    });
  }

  const rejected: unknown[] = [
    undefined,
    null,
    42,
    ['/docs'],
    '',
    'docs',
    ' /docs',
    '//evil.example.com',
    '//evil.example.com/path',
    '/\\evil.example.com',
    '\\\\evil.example.com',
    '\\/evil.example.com',
    '/docs\\..\\x',
    'https://evil.example.com',
    'http:/evil.example.com',
    'javascript:alert(1)',
    'data:text/html,hi',
    '/\t/evil.example.com',
    '/\n/evil.example.com',
    '/docs\r\nSet-Cookie: x=1',
    '/docs\u0000',
    '/docs\u007f',
    '/.//evil.example.com',
    '/./\\evil.example.com',
    `/${'a'.repeat(3000)}`,
  ];
  for (const input of rejected) {
    const label = JSON.stringify(input) ?? String(input);
    test(`rejects ${label.length > 40 ? `${label.slice(0, 20)}… (${label.length} chars)` : label}`, () => {
      assert.equal(safeNext(input), '/');
      assert.equal(safeNext(input, '/home'), '/home');
    });
  }
});

describe('hasGroup', () => {
  test('exact membership only', () => {
    const claims = { groups: ['admins', 'family'] };
    assert.equal(hasGroup(claims, 'admins'), true);
    assert.equal(hasGroup(claims, 'family'), true);
    assert.equal(hasGroup(claims, 'admin'), false);
    assert.equal(hasGroup(claims, 'Admins'), false);
    assert.equal(hasGroup({ groups: [] }, 'admins'), false);
    assert.equal(hasGroup(undefined, 'admins'), false);
    assert.equal(hasGroup(null, 'admins'), false);
    assert.equal(hasGroup({} as { groups: string[] }, 'admins'), false);
  });
});

describe('readCookie', () => {
  test('reads one cookie from a Cookie header', () => {
    assert.equal(readCookie('a=1; oidc_tx=v1.abc; b=2', 'oidc_tx'), 'v1.abc');
    assert.equal(readCookie('oidc_tx="quoted"', 'oidc_tx'), 'quoted');
    assert.equal(readCookie('xoidc_tx=1', 'oidc_tx'), undefined);
    assert.equal(readCookie(undefined, 'oidc_tx'), undefined);
    assert.equal(readCookie(null, 'oidc_tx'), undefined);
  });
});
