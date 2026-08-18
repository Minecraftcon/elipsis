/**
 * @module
 * ============================================================================
 * ELIPSIS - Pure TypeScript Embeddable Tor Client & Hidden Services Engine
 * ============================================================================
 * Complete zero-dependency Tor client implementation for Deno, Node.js,
 * Cloudflare Workers, and Supabase Edge Functions.
 * ============================================================================
 */

// Core Client & Proxy Helpers
export {
  /** Main Tor Client Orchestrator managing circuits, streams, and HTTP requests */
  TorClient,
  /** Helper to immediately spin up a standalone SOCKS5 proxy server */
  startSocksProxy,
  /** Helper to immediately spin up a standalone HTTP / HTTPS CONNECT proxy server */
  startHttpProxy,
} from "./client/tor_client.ts";

export {
  /** Anonymous HTTP/1.1 request client over Tor streams */
  TorHttpClient,
} from "./client/http.ts";
export type {
  /** Parsed HTTP response from TorHttpClient */
  TorHttpResponse,
} from "./client/http.ts";

export {
  /** Embedded SOCKS5 proxy server */
  TorSocksServer,
} from "./client/socks5.ts";
export type {
  /** Configuration options for TorSocksServer */
  SocksServerOptions,
} from "./client/socks5.ts";

export {
  /** Embedded HTTP / HTTPS CONNECT forward proxy server */
  TorHttpProxyServer,
} from "./client/http_proxy.ts";
export type {
  /** Configuration options for TorHttpProxyServer */
  HttpProxyServerOptions,
} from "./client/http_proxy.ts";

// Edge Integration & Web Proxy Gateway
export {
  /** Get or initialize singleton TorClient for Edge Functions */
  getEdgeTorClient,
  /** Higher-order wrapper injecting TorClient into Deno.serve request handlers */
  withTor,
} from "./edge/middleware.ts";

export {
  /** Creates an HTTP API gateway proxy request handler */
  createTorEdgeProxyHandler,
} from "./edge/proxy_handler.ts";
export type {
  /** Configuration options for Edge proxy handler */
  EdgeProxyOptions,
} from "./edge/proxy_handler.ts";

export {
  /** Lightweight memory presets optimized for Edge environments */
  EDGE_FUNCTION_PRESETS,
} from "./edge/config.ts";

// Circuit & Transport
export {
  /** Tor Circuit manager for multi-hop onion routing */
  TorCircuit,
} from "./circuit/circuit.ts";

export {
  /** Multi-hop circuit builder engine */
  CircuitBuilder,
} from "./circuit/builder.ts";

export {
  /** Cryptographic hop representation in a circuit */
  Hop,
} from "./circuit/hop.ts";

export type {
  /** Cryptographic state interface for a single circuit hop */
  CircuitHopCrypto,
} from "./protocol/relay_cell.ts";

export {
  /** Raw TLS link connection handling Tor link protocol v4/v5 */
  TorLinkConnection,
} from "./transport/link.ts";

export type {
  /** Resolved DNS record returned by anonymous Tor DNS lookup */
  DnsAnswer,
} from "./stream/dns.ts";

export {
  /** Tor Relay cell command types */
  RelayCommand,
  /** Tor Cell command types */
  CellCommand,
  /** Circuit destroy reason codes */
  DestroyReason,
} from "./protocol/constants.ts";

export type {
  /** Structured decoded Relay Cell payload */
  RelayCell,
} from "./protocol/relay_cell.ts";

export type {
  /** Raw Tor wire cell structure */
  TorCell,
} from "./protocol/cell.ts";

export {
  /** Running cryptographic digest state */
  TorDigest,
} from "./crypto/digest.ts";

export {
  /** Running AES-CTR stream cipher */
  TorStreamCipher,
} from "./crypto/cipher.ts";

// Hidden Services (v3 .onion)
export {
  /** Parse and validate a 56-character v3 .onion address */
  parseOnionV3Address,
  /** Encode a public key into a v3 .onion hostname */
  encodeOnionV3Address,
  /** Compute the 2-byte SHA3 checksum for a v3 onion address */
  computeOnionV3Checksum,
} from "./hs/address.ts";
export type {
  /** Decoded and validated v3 onion address payload */
  ParsedOnionV3Address,
} from "./hs/address.ts";

export {
  /** Calculate current consensus time period */
  getCurrentTimePeriod,
  /** Derive blinded Ed25519 public key */
  deriveBlindedPublicKey,
  /** Derive subcredential from public key and blinded key */
  deriveSubcredential,
  /** Compute HSDir descriptor index */
  buildHsIndex,
  /** Compute relay hsdir_index */
  buildHsdirIndex,
} from "./hs/blinding.ts";

export {
  /** Orchestrates end-to-end v3 hidden service rendezvous and connections */
  HsOrchestrator,
} from "./hs/orchestrator.ts";
export type {
  /** Options for configuring Hidden Service orchestrator */
  HsOrchestratorOptions,
} from "./hs/orchestrator.ts";

// Ntor Cryptography Primitives
export {
  /** Generate client ephemeral handshake for CREATE2 or RELAY_EXTEND2 */
  createNtorClientHandshake,
  /** Derive symmetric keys and verify server AUTH MAC */
  completeNtorClientHandshake,
  /** Protocol identifier string */
  PROTOID,
  /** HMAC MAC key */
  T_MAC,
  /** HMAC Key extraction */
  T_KEY,
  /** HMAC Verification key */
  T_VERIFY,
  /** HKDF key expansion context */
  M_EXPAND,
  /** Server role string */
  SERVER_STR,
} from "./crypto/ntor.ts";
export type {
  /** State retained between CREATE2 and CREATED2 */
  NtorClientState,
  /** Derived symmetric keys for a circuit hop */
  DerivedHopKeys,
} from "./crypto/ntor.ts";

// Structured Logging & Tracing Subsystem
export {
  /** Global logger instance */
  logger,
  /** Structured logging engine */
  LoggerService,
  /** Log severity levels */
  LogLevel,
} from "./common/logger.ts";
export type {
  /** Subsystem category */
  LogCategory,
  /** Structured log entry */
  LogEntry,
  /** Custom log handler callback */
  LogHandler,
} from "./common/logger.ts";

// Core Enums, Types & Protocol Errors
export {
  /** Security and performance mode preset */
  SecurityMode,
  /** Connection allocation strategy */
  ConnectionMode,
} from "./common/types.ts";

export type {
  /** TorClient initialization options */
  TorClientOptions,
  /** Relay metadata */
  RelayInfo,
  /** Established hop */
  CircuitHop,
  /** Directory cache adapter */
  DirectoryCache,
  /** Bidirectional stream abstraction */
  TorStream,
  /** Anonymous fetch options */
  TorFetchOptions,
} from "./common/types.ts";

export {
  /** Base Tor error */
  TorError,
  /** Protocol violation error */
  TorProtocolError,
  /** Circuit error */
  CircuitError,
  /** Stream error */
  StreamError,
  /** Directory fetch error */
  DirectoryError,
  /** Cryptographic error */
  CryptoError,
  /** Hidden service error */
  HiddenServiceError,
} from "./common/errors.ts";

export {
  /** Fast Fallback Directory Relays */
  DEFAULT_FALLBACK_RELAYS,
} from "./directory/authorities.ts";
