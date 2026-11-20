// Internal: AES-256-GCM sealing for the short-lived login transaction cookie.
// Not part of the public API (no package.json export points here).

import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';

const VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;
const KEY_INFO = 'espired-shared/oidc-transaction/v1';

/** Derives the 32-byte AES key from the app's cookie secret with HKDF-SHA256. */
export function deriveKey(secret: string): Buffer {
  return Buffer.from(hkdfSync('sha256', Buffer.from(secret, 'utf8'), Buffer.alloc(0), KEY_INFO, 32));
}

/** Encrypts and authenticates `payload` as JSON. `aad` binds the value to its cookie name. */
export function seal(key: Buffer, aad: string, payload: unknown): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const body = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
  return `${VERSION}.${Buffer.concat([iv, body, cipher.getAuthTag()]).toString('base64url')}`;
}

/** Returns the decrypted JSON value, or undefined if the value is malformed or was tampered with. */
export function unseal(key: Buffer, aad: string, sealed: string): unknown {
  const prefix = `${VERSION}.`;
  if (!sealed.startsWith(prefix)) return undefined;
  const encoded = sealed.slice(prefix.length);
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) return undefined;
  const raw = Buffer.from(encoded, 'base64url');
  if (raw.length <= IV_BYTES + TAG_BYTES) return undefined;
  const iv = raw.subarray(0, IV_BYTES);
  const tag = raw.subarray(raw.length - TAG_BYTES);
  const body = raw.subarray(IV_BYTES, raw.length - TAG_BYTES);
  try {
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(body), decipher.final()]).toString('utf8');
    return JSON.parse(plain) as unknown;
  } catch {
    return undefined;
  }
}
