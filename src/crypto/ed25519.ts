/**
 * Ed25519 cryptographic routines for Tor identity verification and v3 Onion services.
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
} from "node:crypto";
import { CryptoError } from "../common/errors.ts";

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const PKCS8_ED25519_PREFIX = Buffer.from("302e020100300506032b657004220420", "hex");

export function importRawEd25519Public(rawKey: Uint8Array) {
  if (rawKey.length !== 32) {
    throw new CryptoError(`Ed25519 public key must be 32 bytes, got ${rawKey.length}`);
  }
  const spkiDer = Buffer.concat([SPKI_ED25519_PREFIX, Buffer.from(rawKey)]);
  return createPublicKey({ key: spkiDer, format: "der", type: "spki" });
}

export function importRawEd25519Private(rawKey: Uint8Array) {
  if (rawKey.length !== 32) {
    throw new CryptoError(`Ed25519 private key must be 32 bytes, got ${rawKey.length}`);
  }
  const pkcs8Der = Buffer.concat([PKCS8_ED25519_PREFIX, Buffer.from(rawKey)]);
  return createPrivateKey({ key: pkcs8Der, format: "der", type: "pkcs8" });
}

export function verifyEd25519(
  data: Uint8Array,
  publicKey: Uint8Array,
  signature: Uint8Array
): boolean {
  try {
    const pubKeyObj = importRawEd25519Public(publicKey);
    return verify(null, Buffer.from(data), pubKeyObj, Buffer.from(signature));
  } catch (_e) {
    return false;
  }
}

export function signEd25519(data: Uint8Array, privateKey: Uint8Array): Uint8Array {
  const privKeyObj = importRawEd25519Private(privateKey);
  const signature = sign(null, Buffer.from(data), privKeyObj);
  return new Uint8Array(signature);
}

export function generateEd25519KeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
  const kp = generateKeyPairSync("ed25519");
  const rawPub = new Uint8Array(kp.publicKey.export({ type: "spki", format: "der" }).subarray(-32));
  const rawPriv = new Uint8Array(kp.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32));
  return { publicKey: rawPub, privateKey: rawPriv };
}
