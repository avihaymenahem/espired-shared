// @espired/shared/auth/express — Express adapter.
// `express` is used for types only; nothing here imports it at runtime.
import { readCookie } from './core.js';
import { defaultOnError, describeError, ERROR_HEADERS } from './http.js';
function routePath(path) {
    return path.length > 1 && path.endsWith('/') ? path.slice(0, -1) : path;
}
/**
 * Returns middleware that serves `GET /login?next=` and `GET /callback` relative to where it is
 * mounted, e.g. `app.use('/auth/oidc', oidcRouter({ oidc, onLogin }))`. Other requests fall through.
 */
export function oidcRouter(options) {
    const { oidc, onLogin } = options;
    const onError = options.onError ?? defaultOnError;
    function fail(req, res, err) {
        try {
            onError(err, req);
        }
        catch {
            // a broken error hook must not break the response
        }
        if (res.headersSent) {
            res.end();
            return;
        }
        const { status, message } = describeError(err);
        // Drop any cookie onLogin may have set before failing; only clear the transaction.
        res.setHeader('Set-Cookie', oidc.clearCookie().header);
        res.status(status).set(ERROR_HEADERS).send(message);
    }
    async function login(req, res) {
        try {
            const next = new URL(req.originalUrl, 'http://request.invalid').searchParams.get('next');
            const { url, cookie } = await oidc.beginLogin({ next });
            res.append('Set-Cookie', cookie.header);
            res.set('Cache-Control', 'no-store');
            res.redirect(302, url);
        }
        catch (err) {
            fail(req, res, err);
        }
    }
    async function callback(req, res) {
        try {
            // Never built from the Host header: the configured redirect URI is the base.
            const currentUrl = new URL(req.originalUrl, oidc.redirectUri);
            const result = await oidc.completeLogin(currentUrl, readCookie(req.headers.cookie, oidc.cookieName));
            res.append('Set-Cookie', oidc.clearCookie().header);
            const outcome = await onLogin(result.claims, req, res, { next: result.next, idToken: result.idToken });
            if (res.headersSent)
                return;
            res.set('Cache-Control', 'no-store');
            res.redirect(302, outcome?.redirect ?? result.next);
        }
        catch (err) {
            fail(req, res, err);
        }
    }
    return function oidcRouterMiddleware(req, res, next) {
        if (req.method !== 'GET')
            return next();
        const path = routePath(req.path);
        if (path === '/login') {
            void login(req, res).catch(next);
        }
        else if (path === '/callback') {
            void callback(req, res).catch(next);
        }
        else {
            next();
        }
    };
}
