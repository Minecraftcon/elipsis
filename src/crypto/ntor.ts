/**
 * @module
 * Implementation of Tor ntor circuit handshake (Tor Protocol Specification Section 5.1.4).
 * Handles ephemeral key generation, secret input calculation, authentication verification,
 * and key material derivation for circuit hops.
 */
import {
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  type KeyObject,
} from "node:crypto";
import { constantTimeEqual, hkdfSha256, hmacSha256, sha256 } from "./utils.ts";
import { CryptoError } from "../common/errors.ts";

const PKCS8_X25519_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
const SPKI_X25519_PREFIX = Buffer.from("302a300506032b656e032100", "hex");

/** Tor ntor handshake protocol identifier string */
export const PROTOID: Uint8Array = new TextEncoder().encode("ntor-curve25519-sha256-1");
/** HMAC key for ntor MAC calculation */
export const T_MAC: Uint8Array = new TextEncoder().encode("ntor-curve25519-sha256-1:mac");
/** HMAC key for ntor key extraction */
export const T_KEY: Uint8Array = new TextEncoder().encode("ntor-curve25519-sha256-1:key_extract");
/** HMAC key for ntor verification */
export const T_VERIFY: Uint8Array = new TextEncoder().encode("ntor-curve25519-sha256-1:verify");
/** Context string for ntor HKDF key expansion */
export const M_EXPAND: Uint8Array = new TextEncoder().encode("ntor-curve25519-sha256-1:key_expand");
/** Server role context string */
export const SERVER_STR: Uint8Array = new TextEncoder().encode("Server");

/**
 * State retained by the client between sending CREATE2 and receiving CREATED2.
 */
export interface NtorClientState {
  /** 32-byte client ephemeral scalar secret */
  ephemeralPrivateKey: Uint8Array;
  /** 32-byte client ephemeral public key (X) */
  ephemeralPublicKey: Uint8Array;
  /** 20-byte target relay RSA-1024 identity hash */
  relayIdentity: Uint8Array;
  /** 32-byte target relay Curve25519 static ntor onion key (B) */
  relayNtorOnionKey: Uint8Array;
}

/**
 * Derived cryptographic keys and running digest states for an established hop.
 */
export interface DerivedHopKeys {
  /** 20-byte forward running digest state (Df) */
  forwardDigest: Uint8Array;
  /** 20-byte backward running digest state (Db) */
  backwardDigest: Uint8Array;
  /** 16-byte forward AES-128/256 cipher key (Kf) */
  forwardKey: Uint8Array;
  /** 16-byte backward AES-128/256 cipher key (Kb) */
  backwardKey: Uint8Array;
  /** 32-byte optional key hash (KH) */
  keyHash?: Uint8Array;
}

function importRawX25519Private(rawKey: Uint8Array): KeyObject {
  const der = Buffer.concat([PKCS8_X25519_PREFIX, Buffer.from(rawKey)]);
  return createPrivateKey({ key: der, format: "der", type: "pkcs8" });
}

function importRawX25519Public(rawKey: Uint8Array): KeyObject {
  const der = Buffer.concat([SPKI_X25519_PREFIX, Buffer.from(rawKey)]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

function computeX25519(privKeyBytes: Uint8Array, pubKeyBytes: Uint8Array): Uint8Array {
  const priv = importRawX25519Private(privKeyBytes);
  const pub = importRawX25519Public(pubKeyBytes);
  const secret = diffieHellman({ privateKey: priv, publicKey: pub });
  return new Uint8Array(secret);
}

import { logger } from "../common/logger.ts";

/**
 * Generate client handshake payload for CREATE2 or RELAY_EXTEND2 cells.
 * Returns 84-byte client handshake payload (NODE_ID[20] | KEYID[32] | CLIENT_PK[32]).
 * @param relayIdentity 20-byte RSA-1024 identity fingerprint of the relay
 * @param relayNtorOnionKey 32-byte Curve25519 static ntor onion key
 * @returns Object containing 84-byte client handshake and state for completion
 */
export function createNtorClientHandshake(
  relayIdentity: Uint8Array,
  relayNtorOnionKey: Uint8Array
): { clientHandshake: Uint8Array; state: NtorClientState } {
  if (relayIdentity.length !== 20) {
    throw new CryptoError(`Relay identity must be 20 bytes, got ${relayIdentity.length}`);
  }
  if (relayNtorOnionKey.length !== 32) {
    throw new CryptoError(`Relay ntor onion key must be 32 bytes, got ${relayNtorOnionKey.length}`);
  }

  logger.mechanism(
    "Curve25519 Ntor Handshake Generation",
    "Generating ephemeral X25519 keypair for 1-way forward secrecy (tor-spec Section 5.1.4)"
  );

  const keyPair = generateKeyPairSync("x25519");
  const rawPriv = new Uint8Array(
    keyPair.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32)
  );
  const rawPub = new Uint8Array(
    keyPair.publicKey.export({ type: "spki", format: "der" }).subarray(-32)
  );

  const clientHandshake = new Uint8Array(20 + 32 + 32);
  clientHandshake.set(relayIdentity, 0);
  clientHandshake.set(relayNtorOnionKey, 20);
  clientHandshake.set(rawPub, 52);

  const state: NtorClientState = {
    ephemeralPrivateKey: rawPriv,
    ephemeralPublicKey: rawPub,
    relayIdentity,
    relayNtorOnionKey,
  };

  logger.trace("NTOR", `Client handshake created: 84 bytes (NodeID + NTOR_KEY + ClientPK)`);
  return { clientHandshake, state };
}

/**
 * Complete ntor handshake using the server response (CREATED2 / RELAY_EXTENDED2).
 * Server payload is 64 bytes (SERVER_PK[32] | AUTH[32]).
 * Derives forward/backward digests and AES-CTR keys.
 * @param serverHandshake 64-byte payload received from server
 * @param state Client state returned from createNtorClientHandshake
 * @returns Derived cryptographic keys and forward/backward digest seeds
 */
export function completeNtorClientHandshake(
  serverHandshake: Uint8Array,
  state: NtorClientState
): DerivedHopKeys {
  if (serverHandshake.length !== 64) {
    throw new CryptoError(`Server handshake must be 64 bytes, got ${serverHandshake.length}`);
  }

  const serverEphemeralPub = serverHandshake.subarray(0, 32); // Y
  const serverAuth = serverHandshake.subarray(32, 64); // AUTH

  const x = state.ephemeralPrivateKey;
  const X = state.ephemeralPublicKey;
  const B = state.relayNtorOnionKey;
  const ID = state.relayIdentity;
  const Y = serverEphemeralPub;

  logger.mechanism(
    "Ntor Key Derivation (HKDF-SHA256)",
    "Computing Diffie-Hellman secret_input = EXP(Y,x) | EXP(B,x) and verifying relay AUTH MAC"
  );

  // Compute EXP(Y, x) and EXP(B, x)
  const expYx = computeX25519(x, Y);
  const expBx = computeX25519(x, B);

  // secret_input = EXP(Y,x) | EXP(B,x) | ID | B | X | Y | PROTOID
  const secretInputLen = 32 + 32 + 20 + 32 + 32 + 32 + PROTOID.length;
  const secretInput = new Uint8Array(secretInputLen);
  let offset = 0;

  secretInput.set(expYx, offset);
  offset += 32;
  secretInput.set(expBx, offset);
  offset += 32;
  secretInput.set(ID, offset);
  offset += 20;
  secretInput.set(B, offset);
  offset += 32;
  secretInput.set(X, offset);
  offset += 32;
  secretInput.set(Y, offset);
  offset += 32;
  secretInput.set(PROTOID, offset);

  // verify = H(secret_input, t_verify) = HMAC-SHA256(t_verify, secret_input)
  const verify = hmacSha256(T_VERIFY, secretInput);

  // auth_input = verify | ID | B | Y | X | PROTOID | "Server"
  const authInputLen = 32 + 20 + 32 + 32 + 32 + PROTOID.length + SERVER_STR.length;
  const authInput = new Uint8Array(authInputLen);
  offset = 0;

  authInput.set(verify, offset);
  offset += 32;
  authInput.set(ID, offset);
  offset += 20;
  authInput.set(B, offset);
  offset += 32;
  authInput.set(Y, offset);
  offset += 32;
  authInput.set(X, offset);
  offset += 32;
  authInput.set(PROTOID, offset);
  offset += PROTOID.length;
  authInput.set(SERVER_STR, offset);

  const expectedAuth = hmacSha256(T_MAC, authInput);

  if (!constantTimeEqual(expectedAuth, serverAuth)) {
    logger.error("NTOR", "Relay AUTH mismatch: possible MitM or corrupted handshake!");
    throw new CryptoError("ntor authentication verification failed! Server auth mismatch.");
  }

  logger.debug("NTOR", "✓ Relay AUTH MAC verified successfully.");

  // Derive keys using HKDF-SHA256:
  // key_material = HKDF-SHA256(secret_input, t_key, M_expand, length = 20 + 20 + 16 + 16 + 32 = 104 bytes)
  const keyMaterial = hkdfSha256(secretInput, T_KEY, M_EXPAND, 104);
  logger.trace("NTOR", "✓ Hop key material derived (Df, Db, Kf, Kb, KH)");

  return {
    forwardDigest: keyMaterial.subarray(0, 20), // Df
    backwardDigest: keyMaterial.subarray(20, 40), // Db
    forwardKey: keyMaterial.subarray(40, 56), // Kf
    backwardKey: keyMaterial.subarray(56, 72), // Kb
    keyHash: keyMaterial.subarray(72, 104), // KH
  };
}
