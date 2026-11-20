/** Derives the 32-byte AES key from the app's cookie secret with HKDF-SHA256. */
export declare function deriveKey(secret: string): Buffer;
/** Encrypts and authenticates `payload` as JSON. `aad` binds the value to its cookie name. */
export declare function seal(key: Buffer, aad: string, payload: unknown): string;
/** Returns the decrypted JSON value, or undefined if the value is malformed or was tampered with. */
export declare function unseal(key: Buffer, aad: string, sealed: string): unknown;
