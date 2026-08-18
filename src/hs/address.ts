/**
 * Tor v3 Hidden Service (.onion) address parser and validator (rend-spec-v3 Section 6).
 */
import { decodeBase32, encodeBase32 } from "../crypto/utils.ts";
import { sha3_256 } from "../crypto/sha3.ts";
import { HiddenServiceError } from "../common/errors.ts";

const ONION_CHECKSUM_PREFIX = new TextEncoder().encode(".onion checksum");

/**
 * Decoded and validated v3 Onion Service address payload.
 */
export interface ParsedOnionV3Address {
  /** 32-byte Ed25519 identity public key */
  publicKey: Uint8Array;
  /** 2-byte SHA3 checksum */
  checksum: Uint8Array;
  /** Onion protocol version (always 3) */
  version: number;
  /** Canonical hostname (e.g. "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion") */
  hostname: string;
}

/**
 * Compute the 2-byte checksum for a v3 onion address.
 * checksum = H(".onion checksum" | pubkey | version)[:2]
 * @param pubkey 32-byte Ed25519 public key
 * @param version Protocol version (default: 3)
 * @returns 2-byte SHA3 checksum
 */
export function computeOnionV3Checksum(pubkey: Uint8Array, version = 3): Uint8Array {
  const input = new Uint8Array(ONION_CHECKSUM_PREFIX.length + 32 + 1);
  input.set(ONION_CHECKSUM_PREFIX, 0);
  input.set(pubkey, ONION_CHECKSUM_PREFIX.length);
  input[input.length - 1] = version;

  const hash = sha3_256(input);
  return hash.subarray(0, 2);
}

/**
 * Parse and validate a 56-character v3 .onion domain name or URL.
 * @param address 56-character Base32 onion address or URL
 * @returns Parsed and cryptographically verified address components
 */
export function parseOnionV3Address(address: string): ParsedOnionV3Address {
  let cleanAddress = address.trim().toLowerCase();
  
  // Strip http:// or https:// if provided
  cleanAddress = cleanAddress.replace(/^https?:\/\//, "");
  // Strip path, query params, and port if provided
  cleanAddress = cleanAddress.split("/")[0].split("?")[0].split(":")[0];

  if (cleanAddress.endsWith(".onion")) {
    cleanAddress = cleanAddress.substring(0, cleanAddress.length - 6);
  }

  if (cleanAddress.length !== 56) {
    throw new HiddenServiceError(
      `Invalid v3 onion address length: expected 56 characters, got ${cleanAddress.length} for '${cleanAddress}'`
    );
  }

  const rawBytes = decodeBase32(cleanAddress);
  if (rawBytes.length !== 35) {
    throw new HiddenServiceError(`Decoded onion address must be 35 bytes, got ${rawBytes.length}`);
  }

  const publicKey = rawBytes.subarray(0, 32);
  const checksum = rawBytes.subarray(32, 34);
  const version = rawBytes[34];

  if (version !== 3) {
    throw new HiddenServiceError(`Unsupported hidden service version: v${version} (only v3 is supported)`);
  }

  const expectedChecksum = computeOnionV3Checksum(publicKey, version);
  if (
    checksum[0] !== expectedChecksum[0] ||
    checksum[1] !== expectedChecksum[1]
  ) {
    throw new HiddenServiceError("Invalid onion address checksum. Address may be mistyped or corrupted.");
  }

  return {
    publicKey,
    checksum,
    version,
    hostname: `${cleanAddress}.onion`,
  };
}

/**
 * Encode an Ed25519 public key into a canonical 56-character v3 .onion address.
 * @param publicKey 32-byte Ed25519 public key
 * @returns 56-character .onion hostname
 */
export function encodeOnionV3Address(publicKey: Uint8Array): string {
  if (publicKey.length !== 32) {
    throw new HiddenServiceError(`Public key must be 32 bytes, got ${publicKey.length}`);
  }

  const checksum = computeOnionV3Checksum(publicKey, 3);
  const raw = new Uint8Array(35);
  raw.set(publicKey, 0);
  raw.set(checksum, 32);
  raw[34] = 3;

  return `${encodeBase32(raw)}.onion`;
}
