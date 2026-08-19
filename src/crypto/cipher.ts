/**
 * Stream cipher for Tor cell encryption and decryption.
 * Uses AES-128-CTR with a continuous running counter state and zero IV.
 */
import { createCipheriv, type Cipheriv } from "node:crypto";

/**
 * AES-CTR stream cipher maintaining a running counter state across Tor relay cells.
 */
export class TorStreamCipher {
  private cipher: Cipheriv;

  /**
   * Constructs a new TorStreamCipher.
   * @param key 16-byte (AES-128) or 32-byte (AES-256) symmetric key
   * @param algorithm Cipher algorithm (default: aes-128-ctr)
   * @param iv Optional initial vector
   */
  constructor(key: Uint8Array, algorithm?: "aes-128-ctr" | "aes-256-ctr", iv?: Uint8Array) {
    const initialIv = iv || new Uint8Array(16); // 16 zero bytes default
    const algo = algorithm || (key.length === 32 ? "aes-256-ctr" : "aes-128-ctr");
    this.cipher = createCipheriv(algo, key, initialIv);
    this.cipher.setAutoPadding(false);
  }

  /**
   * Process a chunk of bytes in-place or return a newly encrypted/decrypted Uint8Array.
   * @param data Input byte buffer
   * @returns Transformed byte buffer
   */
  process(data: Uint8Array): Uint8Array {
    const output = this.cipher.update(data);
    return new Uint8Array(output.buffer, output.byteOffset, output.byteLength);
  }
}

/**
 * Decrypt or encrypt a block of data with AES-256-CTR.
 * @param key 32-byte encryption key
 * @param iv 16-byte IV
 * @param data Input bytes
 * @returns Transformed bytes
 */
export function cryptAes256Ctr(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
  const cipher = new TorStreamCipher(key, "aes-256-ctr", iv);
  return cipher.process(data);
}

