/**
 * Cryptographic utility functions for Tor protocol operations.
 * Fully compatible with Deno, Node.js (v18+), and Supabase Edge Functions.
 */
import {
  createHash,
  createHmac,
  randomBytes as nodeRandomBytes,
  timingSafeEqual,
} from "node:crypto";

/**
 * Generate cryptographically secure random bytes.
 */
export function randomBytes(length: number): Uint8Array {
  return new Uint8Array(nodeRandomBytes(length));
}

/**
 * Perform constant-time buffer equality check.
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  return timingSafeEqual(a, b);
}

/**
 * Compute SHA-1 hash.
 */
export function sha1(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha1").update(data).digest());
}

/**
 * Compute SHA-256 hash.
 */
export function sha256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha256").update(data).digest());
}

/**
 * Compute HMAC-SHA256.
 */
export function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return new Uint8Array(createHmac("sha256", key).update(data).digest());
}

/**
 * RFC 5869 HKDF-SHA256 implementation.
 */
export function hkdfSha256(
  ikm: Uint8Array,
  salt: Uint8Array,
  info: Uint8Array,
  length: number
): Uint8Array {
  // Extract
  const prk = hmacSha256(salt.length === 0 ? new Uint8Array(32) : salt, ikm);

  // Expand
  const okm = new Uint8Array(length);
  let previousT: Uint8Array = new Uint8Array(0);
  let offset = 0;
  let counter = 1;

  while (offset < length) {
    const toHash = new Uint8Array(previousT.length + info.length + 1);
    toHash.set(previousT, 0);
    toHash.set(info, previousT.length);
    toHash[toHash.length - 1] = counter;

    const currentT = hmacSha256(prk, toHash);
    previousT = new Uint8Array(currentT);
    const sliceLen = Math.min(previousT.length, length - offset);
    okm.set(previousT.subarray(0, sliceLen), offset);
    offset += sliceLen;
    counter++;
  }

  return okm;
}

/**
 * Base32 alphabet for Tor (RFC 4648 lower case, no padding).
 */
const RFC4648_ALPHABET = "abcdefghijklmnopqrstuvwxyz234567";

/**
 * Decode Base32 string to Uint8Array.
 */
export function decodeBase32(str: string): Uint8Array {
  const cleanStr = str.toLowerCase().replace(/=/g, "");
  let bits = 0;
  let value = 0;
  const output: number[] = [];

  for (let i = 0; i < cleanStr.length; i++) {
    const idx = RFC4648_ALPHABET.indexOf(cleanStr[i]);
    if (idx === -1) {
      throw new Error(`Invalid base32 character: ${cleanStr[i]}`);
    }
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }

  return new Uint8Array(output);
}

/**
 * Encode Uint8Array to Base32 string.
 */
export function encodeBase32(data: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let output = "";

  for (let i = 0; i < data.length; i++) {
    value = (value << 8) | data[i];
    bits += 8;

    while (bits >= 5) {
      output += RFC4648_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += RFC4648_ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Decode Base64 string to Uint8Array.
 */
export function decodeBase64(str: string): Uint8Array {
  let base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return new Uint8Array(Buffer.from(base64, "base64"));
}

/**
 * Encode Uint8Array to Base64 string.
 */
export function encodeBase64(data: Uint8Array): string {
  return Buffer.from(data).toString("base64");
}

/**
 * Encode Uint8Array to Hex string.
 */
export function encodeHex(data: Uint8Array): string {
  return Buffer.from(data).toString("hex");
}

/**
 * Decode Hex string to Uint8Array.
 */
export function decodeHex(hex: string): Uint8Array {
  const cleanHex = hex.replace(/[\s:]/g, "");
  return new Uint8Array(Buffer.from(cleanHex, "hex"));
}
