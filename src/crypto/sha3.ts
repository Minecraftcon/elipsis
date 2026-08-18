/**
 * SHA3-256 and SHAKE-256 implementations for Tor v3 hidden services.
 */
import { createHash } from "node:crypto";

export function sha3_256(data: Uint8Array): Uint8Array {
  return new Uint8Array(createHash("sha3-256").update(data).digest());
}

export function shake256(data: Uint8Array, outputLength: number): Uint8Array {
  return new Uint8Array(
    createHash("shake256", { outputLength }).update(data).digest()
  );
}
