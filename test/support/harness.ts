// Test harness: an in-process oidc-provider shaped like authentik (issuer with a path and a
// trailing slash, a `groups` claim in the profile scope, claims inside the ID token), plus a
// tiny "browser" that follows redirects with plain fetch and a cookie jar.

import { generateKeyPairSync } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import express from 'express';
import Provider from 'oidc-provider';

export const CLIENT_ID = 'test-client';
export const CLIENT_SECRET = 'test-client-secret-0123456789-abcdefghijklmnop';
export const COOKIE_SECRET = 'test-cookie-secret-0123456789-abcdefghijklmnop';
const PREFIX = '/application/o/test';

export interface Account {
  email?: string;
  email_verified?: boolean;
  name?: string;
  preferred_username?: string;
  groups?: string[];
}

export const ACCOUNTS: Record<string, Account> = {
  'user-admin': {
    email: 'owner@example.com',
    email_verified: true,
    name: 'Test Owner',
    preferred_username: 'owner',
    groups: ['admins', 'family'],
  },
  // No groups claim at all.
  'user-plain': { email: 'guest@example.com', email_verified: false, name: 'Guest', preferred_username: 'guest' },
};

export interface Harness {
  /** authentik-style issuer: http://127.0.0.1:PORT/application/o/test/ */
  issuer: string;
  /** Origin of the fake app server. */
  appOrigin: string;
  /** Mutable: which account the fake IdP logs in next. */
  idp: { account: string; failNextDiscovery: boolean };
  /** Replace the app server's request handler. */
  setAppHandler(handler: (req: IncomingMessage, res: ServerResponse) => void): void;
  close(): Promise<void>;
}

function listen(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
  });
}

function closeServer(server: Server): Promise<void> {
  server.closeAllConnections();
  return new Promise((resolve) => server.close(() => resolve()));
}

export async function startHarness(): Promise<Harness> {
  let appHandler: (req: IncomingMessage, res: ServerResponse) => void = (_req, res) => {
    res.statusCode = 404;
    res.end();
  };
  const appServer = createServer((req, res) => appHandler(req, res));
  const appOrigin = `http://127.0.0.1:${await listen(appServer)}`;

  const idpServer = createServer();
  const issuer = `http://127.0.0.1:${await listen(idpServer)}${PREFIX}/`;
  const idp = { account: 'user-admin', failNextDiscovery: false };

  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const provider = new Provider(issuer, {
    clients: [
      {
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uris: [`${appOrigin}/auth/oidc/callback`, `${appOrigin}/api/auth/callback`],
        post_logout_redirect_uris: [`${appOrigin}/`],
        grant_types: ['authorization_code'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_basic',
      },
    ],
    jwks: { keys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'test-key', use: 'sig', alg: 'RS256' } as never] },
    claims: {
      openid: ['sub'],
      email: ['email', 'email_verified'],
      profile: ['name', 'preferred_username', 'groups'],
    },
    // Like authentik's "Include claims in id_token": profile/email claims go into the ID token.
    conformIdTokenClaims: false,
    features: { devInteractions: { enabled: false } },
    interactions: { url: (_ctx, interaction) => `${PREFIX}/interaction/${interaction.uid}` },
    cookies: { keys: ['fake-idp-cookie-key-for-tests-only'] },
    ttl: { AuthorizationCode: 60, AccessToken: 600, IdToken: 600, Interaction: 600, Session: 3600, Grant: 3600 },
    findAccount: async (_ctx, sub) => {
      const account = ACCOUNTS[sub];
      if (!account) return undefined;
      return { accountId: sub, claims: async () => ({ sub, ...account }) };
    },
    renderError: async (ctx, out) => {
      ctx.type = 'text/plain';
      ctx.body = `${out.error}: ${out.error_description ?? ''}`;
    },
  });

  const idpApp = express();
  idpApp.get(`${PREFIX}/.well-known/openid-configuration`, (_req, res, next) => {
    if (!idp.failNextDiscovery) return next();
    idp.failNextDiscovery = false;
    res.status(503).send('unavailable');
  });
  // Auto-finishes login (as idp.account) and consent, so tests can just follow redirects.
  idpApp.get(`${PREFIX}/interaction/:uid`, async (req, res, next) => {
    try {
      const details = await provider.interactionDetails(req, res);
      if (details.prompt.name === 'login') {
        await provider.interactionFinished(req, res, { login: { accountId: idp.account } }, { mergeWithLastSubmission: false });
        return;
      }
      const grant = new provider.Grant({ accountId: details.session!.accountId, clientId: String(details.params.client_id) });
      grant.addOIDCScope(String(details.params.scope));
      const grantId = await grant.save();
      await provider.interactionFinished(req, res, { consent: { grantId } }, { mergeWithLastSubmission: true });
    } catch (err) {
      next(err);
    }
  });
  idpApp.use(PREFIX, provider.callback());
  idpServer.on('request', idpApp);

  return {
    issuer,
    appOrigin,
    idp,
    setAppHandler(handler) {
      appHandler = handler;
    },
    async close() {
      await Promise.all([closeServer(appServer), closeServer(idpServer)]);
    },
  };
}

/**
 * Follows redirects from `authorizationUrl` through the fake IdP (login + consent are
 * auto-finished) and returns the first URL that starts with `stopAt` — the app's callback.
 * Each call uses a fresh cookie jar, i.e. a fresh browser with no IdP session.
 */
export async function authorize(authorizationUrl: string, stopAt: string): Promise<URL> {
  const jar = new Map<string, string>();
  let url = new URL(authorizationUrl);
  for (let hop = 0; hop < 20; hop++) {
    if (url.href.startsWith(stopAt)) return url;
    const headers: Record<string, string> = {};
    if (jar.size > 0) headers.cookie = [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
    const res = await fetch(url, { redirect: 'manual', headers });
    for (const setCookie of res.headers.getSetCookie()) {
      const [pair = '', ...attributes] = setCookie.split(';');
      const eq = pair.indexOf('=');
      const name = pair.slice(0, eq).trim();
      const expires = attributes.find((a) => a.trim().toLowerCase().startsWith('expires='));
      const expired = expires !== undefined && Date.parse(expires.split('=')[1] ?? '') < Date.now();
      if (expired || /max-age=0\b/i.test(setCookie)) jar.delete(name);
      else jar.set(name, pair.slice(eq + 1).trim());
    }
    const location = res.headers.get('location');
    const body = await res.text();
    if (res.status < 300 || res.status >= 400 || !location) {
      throw new Error(`Expected a redirect from ${url.href}, got ${res.status}: ${body.slice(0, 300)}`);
    }
    url = new URL(location, url);
  }
  throw new Error('Too many redirects');
}

/** Returns the `name=value` part of the Set-Cookie header for `name`, or undefined. */
export function setCookieFor(headers: Headers, name: string): string | undefined {
  return headers.getSetCookie().find((c) => c.startsWith(`${name}=`));
}

/** Returns just the value of the Set-Cookie header for `name`. */
export function cookieValue(headers: Headers, name: string): string {
  const header = setCookieFor(headers, name);
  if (!header) throw new Error(`No Set-Cookie for ${name}`);
  return header.slice(name.length + 1).split(';')[0] ?? '';
}
