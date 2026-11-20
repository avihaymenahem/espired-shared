// Internal: maps login errors to short, stack-free HTTP answers for the adapters.

import { OidcAccessDenied, OidcError } from './core.js';

export interface ErrorAnswer {
  status: number;
  message: string;
}

export function describeError(err: unknown): ErrorAnswer {
  if (err instanceof OidcAccessDenied) return { status: 403, message: err.message || 'Access denied.' };
  if (err instanceof OidcError) {
    switch (err.code) {
      case 'invalid_transaction':
      case 'expired_transaction':
      case 'state_mismatch':
        return { status: 400, message: 'Login expired or invalid. Please start the login again.' };
      case 'provider_error':
        return { status: 401, message: 'Login failed.' };
      case 'discovery_failed':
        return { status: 502, message: 'Identity provider unavailable.' };
    }
  }
  return { status: 500, message: 'Login failed.' };
}

/** Default error hook: logs only server-side failures (5xx) so expected rejections stay quiet. */
export function defaultOnError(err: unknown): void {
  if (describeError(err).status >= 500) {
    console.error('[@espired/shared] OIDC login error:', err);
  }
}

export const ERROR_HEADERS: Readonly<Record<string, string>> = {
  'Content-Type': 'text/plain; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};
