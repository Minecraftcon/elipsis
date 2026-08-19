/**
 * Core types and interfaces for the Elipsis Tor engine.
 */

/**
 * Security preset defining anonymity depth vs latency tradeoff.
 */
export enum SecurityMode {
  /** 1-Hop Direct connection to Rendezvous Point (Fastest: ~200-400ms, ideal for scraping & indexing) */
  TURBO_DIRECT = "turbo",
  /** 2-Hop circuit (Guard -> RP) balancing speed and client IP privacy from the RP */
  BALANCED = "balanced",
  /** 3-Hop standard Tor anonymity (Guard -> Middle -> RP) */
  STANDARD = "standard",
  /** 4+ Hops paranoid routing with custom relay chain */
  PARANOID = "paranoid",
}

/**
 * Circuit allocation and multiplexing strategy.
 */
export enum ConnectionMode {
  /** Fresh direct circuit on every stream */
  DIRECT = "direct",
  /** Multiplex multiple streams over active rendezvous circuits */
  MULTIPLEXED = "multiplexed",
  /** Continuously maintained warm circuit pool with 0ms handover */
  POOL = "pool",
}

/**
 * Configuration options for initializing a TorClient instance.
 */
export interface TorClientOptions {
  /** Security and performance mode preset */
  securityMode?: SecurityMode | "turbo" | "balanced" | "standard" | "paranoid";
  /** Explicit number of relay hops (1 to 5, overrides securityMode default if set) */
  relayCount?: number;
  /** Connection and circuit lifecycle strategy */
  connectionMode?: ConnectionMode | "direct" | "multiplexed" | "pool";
  /** If true, dynamically initializes WebAssembly cryptography workers (MTCW) for maximum stream throughput (falls back to pure TS on failure). */
  enableWasm?: boolean;
  /** Directory cache adapter (memory, supabase storage, postgres, etc.) */
  cache?: DirectoryCache;
  /** List of fallback directory mirrors or guards */
  fallbackRelays?: RelayInfo[];
  /** Maximum number of established circuits to keep alive in pool */
  maxPoolCircuits?: number;
  /** Timeout in milliseconds for circuit building */
  circuitBuildTimeoutMs?: number;
  /** Timeout in milliseconds for stream operations */
  streamTimeoutMs?: number;
  /** Whether to enable debug logging */
  debug?: boolean;
}

/**
 * Information describing a single Tor relay node.
 */
export interface RelayInfo {
  /** Nickname of the relay */
  nickname: string;
  /** 20-byte SHA-1 RSA identity fingerprint */
  identityRsa: Uint8Array;
  /** 32-byte Ed25519 identity key (optional in v3 directory specs) */
  identityEd25519?: Uint8Array;
  /** IPv4 or IPv6 string address */
  ip: string;
  /** Onion routing port (ORPort) */
  orPort: number;
  /** Directory port (DirPort) */
  dirPort?: number;
  /** 32-byte Curve25519 Ntor onion key for circuit handshakes */
  ntorOnionKey: Uint8Array;
  /** Relay flags from consensus (e.g. Guard, Exit, Fast, Stable, HSDir) */
  flags: Set<string>;
  /** Microdescriptor SHA256 digest */
  microdescriptorDigest?: Uint8Array;
}

/**
 * Represents an established cryptographic hop in a multi-layer onion circuit.
 */
export interface CircuitHop {
  /** Relay metadata for this hop */
  relay: RelayInfo;
  /** Forward running digest state (Df) */
  forwardDigest: Uint8Array;
  /** Backward running digest state (Db) */
  backwardDigest: Uint8Array;
  /** Forward AES-128/256 cipher key (Kf) */
  forwardKey: Uint8Array;
  /** Backward AES-128/256 cipher key (Kb) */
  backwardKey: Uint8Array;
}

/**
 * Storage adapter interface for caching consensus and relay descriptors.
 */
export interface DirectoryCache {
  /** Retrieve cached consensus document */
  getConsensus(): Promise<string | null>;
  /** Save consensus document with expiration TTL */
  setConsensus(consensus: string, ttlSeconds: number): Promise<void>;
  /** Retrieve cached relay microdescriptors map */
  getMicrodescriptors(): Promise<Map<string, RelayInfo> | null>;
  /** Save relay microdescriptors with expiration TTL */
  setMicrodescriptors(descriptors: Map<string, RelayInfo>, ttlSeconds: number): Promise<void>;
}

/**
 * Bidirectional stream abstraction over an established Tor circuit.
 */
export interface TorStream {
  /** Stream identifier on the circuit */
  streamId: number;
  /** Read next chunk of payload bytes, or null on stream close */
  read(): Promise<Uint8Array | null>;
  /** Write payload bytes across the onion circuit */
  write(data: Uint8Array): Promise<void>;
  /** Gracefully close the stream with an optional reason code */
  close(reason?: number): Promise<void>;
}

/**
 * Options for anonymous HTTP fetch over Tor.
 */
export interface TorFetchOptions extends RequestInit {
  /** Request timeout in milliseconds */
  timeoutMs?: number;
  /** Number of circuit hops to enforce for this request */
  hops?: number;
}
