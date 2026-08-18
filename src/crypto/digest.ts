/**
 * Running cryptographic digest tracker for Tor relay cell integrity checking.
 * Uses high-performance $O(1)$ state cloning (hash.copy()) to achieve ultra-fast throughput.
 */
import { createHash, type Hash } from "node:crypto";

/**
 * High-performance running cryptographic digest.
 * $O(1)$ constant time per cell using native hash state copy.
 */
export class TorDigest {
  private hash: Hash;
  private algorithm: "sha1" | "sha256";

  /**
   * Constructs a new TorDigest with an initial seed.
   * @param seed Seed bytes (e.g. Df, Db from handshake)
   * @param algorithm Hash algorithm (default: sha1)
   */
  constructor(seed: Uint8Array, algorithm: "sha1" | "sha256" = "sha1") {
    this.algorithm = algorithm;
    this.hash = createHash(algorithm);
    this.hash.update(seed);
  }

  /**
   * Add data to running digest and return the full digest.
   */
  update(data: Uint8Array): Uint8Array {
    this.hash.update(data);
    const copy = (this.hash as any).copy();
    return new Uint8Array(copy.digest());
  }

  /**
   * Add data and return the 4-byte digest tag used in Tor relay cells.
   */
  updateAndGetTag(data: Uint8Array): Uint8Array {
    const fullDigest = this.update(data);
    return fullDigest.subarray(0, 4);
  }

  /**
   * Peek at what the 4-byte tag would be for prospective data without mutating state.
   */
  peekTag(data: Uint8Array): Uint8Array {
    const copy = (this.hash as any).copy();
    copy.update(data);
    const digest = new Uint8Array(copy.digest());
    return digest.subarray(0, 4);
  }
}
