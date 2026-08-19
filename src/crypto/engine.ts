import { TorStreamCipher, cryptAes256Ctr } from "./cipher.ts";
import { generateEd25519KeyPair, signEd25519, verifyEd25519 } from "./ed25519.ts";
import { logger } from "../common/logger.ts";
import { Buffer } from "node:buffer";

/**
 * Interface representing a stream cipher (e.g. AES-128-CTR).
 */
export interface StreamCipher {
  process(data: Uint8Array): Uint8Array;
}

/**
 * Interface abstracting all cryptographic operations needed by Elipsis.
 * This allows swapping out the underlying implementation (e.g., node:crypto vs WebAssembly).
 */
export interface CryptoEngine {
  /** Create a stateful stream cipher */
  createStreamCipher(key: Uint8Array, algorithm: "aes-128-ctr" | "aes-256-ctr", iv?: Uint8Array): StreamCipher;
  /** One-shot AES-256-CTR encryption/decryption */
  cryptAes256Ctr(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array;
  
  /** Ed25519 routines */
  verifyEd25519(data: Uint8Array, publicKey: Uint8Array, signature: Uint8Array): boolean;
  signEd25519(data: Uint8Array, privateKey: Uint8Array): Uint8Array;
  generateEd25519KeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  
  /** X25519 (Curve25519) routines for Ntor */
  generateX25519KeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array };
  computeX25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array;
  
  /** Return whether this engine is using hardware/wasm acceleration */
  isAccelerated(): boolean;
}

/**
 * Default Pure TypeScript / Node Crypto engine.
 */
class DefaultCryptoEngine implements CryptoEngine {
  createStreamCipher(key: Uint8Array, algorithm: "aes-128-ctr" | "aes-256-ctr", iv?: Uint8Array): StreamCipher {
    return new TorStreamCipher(key, algorithm, iv);
  }

  cryptAes256Ctr(key: Uint8Array, iv: Uint8Array, data: Uint8Array): Uint8Array {
    return cryptAes256Ctr(key, iv, data);
  }

  verifyEd25519(data: Uint8Array, publicKey: Uint8Array, signature: Uint8Array): boolean {
    return verifyEd25519(data, publicKey, signature);
  }

  signEd25519(data: Uint8Array, privateKey: Uint8Array): Uint8Array {
    return signEd25519(data, privateKey);
  }

  generateEd25519KeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    return generateEd25519KeyPair();
  }

  generateX25519KeyPair(): { publicKey: Uint8Array; privateKey: Uint8Array } {
    // Import dynamically so it doesn't break environments missing node:crypto
    const { generateKeyPairSync } = require("node:crypto");
    const kp = generateKeyPairSync("x25519");
    const rawPub = new Uint8Array(kp.publicKey.export({ type: "spki", format: "der" }).subarray(-32));
    const rawPriv = new Uint8Array(kp.privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32));
    return { publicKey: rawPub, privateKey: rawPriv };
  }

  computeX25519SharedSecret(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    const { diffieHellman, createPrivateKey, createPublicKey } = require("node:crypto");
    const PKCS8_X25519_PREFIX = Buffer.from("302e020100300506032b656e04220420", "hex");
    const SPKI_X25519_PREFIX = Buffer.from("302a300506032b656e032100", "hex");
    
    const derPriv = Buffer.concat([PKCS8_X25519_PREFIX, Buffer.from(privateKey)]);
    const derPub = Buffer.concat([SPKI_X25519_PREFIX, Buffer.from(publicKey)]);
    
    const priv = createPrivateKey({ key: derPriv, format: "der", type: "pkcs8" });
    const pub = createPublicKey({ key: derPub, format: "der", type: "spki" });
    
    return new Uint8Array(diffieHellman({ privateKey: priv, publicKey: pub }));
  }

  isAccelerated(): boolean {
    return false; // Uses Node Crypto bindings but synchronously on main thread
  }
}

// Global active engine instance
let globalEngine: CryptoEngine = new DefaultCryptoEngine();

/**
 * Get the currently active CryptoEngine.
 */
export function getCryptoEngine(): CryptoEngine {
  return globalEngine;
}

/**
 * Initializes the crypto engine. If Wasm is requested, it dynamically attempts
 * to load the Wasm Crypto Engine (from a Base64-inlined blob or module).
 * Falls back to the pure TS DefaultCryptoEngine gracefully.
 */
export async function initCryptoEngine(enableWasm: boolean): Promise<CryptoEngine> {
  if (!enableWasm) {
    logger.trace("WASM-TRACE", "[initCryptoEngine] `enableWasm` flag is false. Skipping Wasm subsystem boot.");
    logger.info("CRYPTO", "Wasm crypto disabled. Using pure TS DefaultCryptoEngine.");
    globalEngine = new DefaultCryptoEngine();
    return globalEngine;
  }

  try {
    logger.trace("WASM-TRACE", "[initCryptoEngine] `enableWasm` is true. Initiating MTCW subsystem boot sequence...");
    logger.trace("WASM-TRACE", "[initCryptoEngine] System Environment Check: Looking for SharedArrayBuffer and Web Worker support...");
    logger.info("CRYPTO", "Attempting to initialize Wasm Crypto Engine...");
    
    // In the future, we will dynamically import the wasm module here:
    // logger.trace("WASM-TRACE", "[initCryptoEngine] Dynamically importing Wasm binary/Base64 stub...");
    // const { WasmCryptoEngine } = await import("./wasm_engine.ts");
    // const wasmEngine = new WasmCryptoEngine();
    // await wasmEngine.init();
    // logger.trace("MTCW-TRACE", "[initCryptoEngine] Spawning Web Worker thread pool for MTCW...");
    // globalEngine = wasmEngine;
    
    // For now, we scaffold the fallback since Wasm is not fully compiled yet.
    logger.trace("WASM-TRACE", "[initCryptoEngine] ERROR: Wasm subsystem not fully implemented yet (missing binary).");
    logger.trace("WASM-TRACE", "[initCryptoEngine] Triggering graceful fallback to DefaultCryptoEngine (Pure TS).");
    logger.warn("CRYPTO", "Wasm Engine not yet bundled. Falling back to DefaultCryptoEngine.");
    globalEngine = new DefaultCryptoEngine();
    return globalEngine;
  } catch (err) {
    logger.error("WASM-TRACE", `[initCryptoEngine] CRITICAL FAILURE during Wasm Boot: ${(err as Error).stack}`);
    logger.trace("WASM-TRACE", "[initCryptoEngine] Triggering graceful fallback to DefaultCryptoEngine (Pure TS) due to exception.");
    logger.warn("CRYPTO", `Failed to load Wasm Crypto Engine: ${(err as Error).message}. Falling back to DefaultCryptoEngine.`);
    globalEngine = new DefaultCryptoEngine();
    return globalEngine;
  }
}
