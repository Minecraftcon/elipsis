/**
 * Main Tor Client Orchestrator.
 * Unites directory consensus, circuit pooling, streams, HTTP fetching, DNS resolution, and Proxy servers.
 */
import { DirectoryCache, RelayInfo, SecurityMode, TorClientOptions, TorStream } from "../common/types.ts";
import { DEFAULT_FALLBACK_RELAYS } from "../directory/authorities.ts";
import { TorError } from "../common/errors.ts";
import { MemoryDirectoryCache } from "../directory/cache/memory_cache.ts";
import { CircuitPool } from "../circuit/pool.ts";
import { CircuitStream } from "../stream/stream.ts";
import { TorDnsResolver, DnsAnswer } from "../stream/dns.ts";
import { TorHttpClient, TorHttpResponse } from "./http.ts";
import { TorSocksServer, SocksServerOptions } from "./socks5.ts";
import { TorHttpProxyServer, HttpProxyServerOptions } from "./http_proxy.ts";
import { TorCircuit } from "../circuit/circuit.ts";
import { HsOrchestrator } from "../hs/orchestrator.ts";
import { fetchConsensusRelays } from "../directory/dir_fetcher.ts";
import { logger } from "../common/logger.ts";

/**
 * Main Pure TypeScript Tor Client Orchestrator.
 * Handles directory consensus, circuit pooling, bidirectional streams, HTTP requests, DNS queries, and proxy servers.
 */
export class TorClient {
  private options: TorClientOptions;
  private cache: DirectoryCache;
  private relays: RelayInfo[] = [];
  private circuitPool: CircuitPool;
  private hsOrchestrator: HsOrchestrator;
  private nextStreamId = 1;
  private socksServer: TorSocksServer | null = null;
  private httpProxyServer: TorHttpProxyServer | null = null;

  /**
   * Initializes a new TorClient with configurable security modes, caching, and timeouts.
   * @param options Client configuration options
   */
  constructor(options: TorClientOptions = {}) {
    this.options = options;
    this.cache = options.cache || new MemoryDirectoryCache();
    this.relays = options.fallbackRelays || DEFAULT_FALLBACK_RELAYS;

    const hopCount = this.getEffectiveHopCount();
    this.circuitPool = new CircuitPool(
      () => this.relays,
      options.maxPoolCircuits || 2,
      5,
      hopCount
    );

    this.hsOrchestrator = new HsOrchestrator(() => this.relays, {
      securityMode: options.securityMode,
      relayCount: options.relayCount,
    });
  }

  /**
   * Resolve effective hop count based on options.
   * @internal
   */
  private getEffectiveHopCount(): number {
    if (typeof this.options.relayCount === "number") {
      return Math.max(1, Math.min(this.options.relayCount, 5));
    }
    switch (this.options.securityMode as any) {
      case SecurityMode.TURBO_DIRECT:
      case "turbo":
      case "direct":
        return 1;
      case SecurityMode.BALANCED:
      case "balanced":
        return 2;
      case SecurityMode.PARANOID:
      case "paranoid":
        return 4;
      case SecurityMode.STANDARD:
      case "standard":
      default:
        return 3;
    }
  }

  /**
   * Dynamically adjust security mode and relay count at runtime.
   * @param mode Security preset (e.g. TURBO_DIRECT, BALANCED, STANDARD, PARANOID)
   * @param relayCount Optional explicit number of hops
   */
  setProfile(mode: any, relayCount?: number): void {
    this.options.securityMode = mode;
    if (typeof relayCount === "number") {
      this.options.relayCount = relayCount;
    }
    const hopCount = this.getEffectiveHopCount();
    this.circuitPool.setHopCount(hopCount);
    this.hsOrchestrator = new HsOrchestrator(() => this.relays, {
      securityMode: this.options.securityMode,
      relayCount: this.options.relayCount,
    });
  }

  /**
   * Initialize directory information and warm up background circuit pool.
   * Downloads the live Tor consensus to get the full relay list.
   */
  async init(): Promise<void> {
    // Try to load from cache first
    const cachedConsensus = await this.cache.getConsensus();
    if (cachedConsensus) {
      return; // Already initialized from cache
    }

    // Fetch live consensus from directory authorities
    try {
      const liveRelays = await fetchConsensusRelays(20000, 800);
      if (liveRelays.length > 0) {
        this.relays = liveRelays;
        // Update circuit pool and HS orchestrator with new relays
        const hopCount = this.getEffectiveHopCount();
        this.circuitPool = new CircuitPool(
          () => this.relays,
          this.options.maxPoolCircuits || 2,
          5,
          hopCount
        );
        this.hsOrchestrator = new HsOrchestrator(() => this.relays, {
          securityMode: this.options.securityMode,
          relayCount: this.options.relayCount,
        });
        await this.circuitPool.prewarm().catch(() => {});
      }
    } catch (e) {
      // Non-fatal — fall back to hardcoded relays
      logger.warn("CLIENT", `Directory bootstrap failed, using fallback relays: ${(e as Error).message}`);
    }
  }

  /**
   * Connect an arbitrary raw TCP stream over a Tor circuit to target host:port.
   * Automatically selects between v3 Hidden Service rendezvous circuits (.onion) and exit circuits.
   * @param targetHost Target hostname, IP, or .onion address
   * @param targetPort Destination TCP port (e.g. 80, 443)
   * @returns Established bidirectional stream
   */
  async connectStream(targetHost: string, targetPort: number, maxRetries = 2): Promise<TorStream> {
    if (this.relays.length <= DEFAULT_FALLBACK_RELAYS.length) {
      await this.init().catch(() => {});
    }

    const isHostOnion = targetHost.toLowerCase().endsWith(".onion");

    if (isHostOnion) {
      // Establish end-to-end Hidden Service circuit via v3 Rendezvous Protocol
      const streamId = this.allocateStreamId();
      const circuit = await this.hsOrchestrator.connectOnionCircuit(
        targetHost,
        this.options.streamTimeoutMs || 25000
      );
      // For onion services, the Tor spec defines the RELAY_BEGIN payload as ':PORT\0' (empty hostname)
      return await CircuitStream.open(
        circuit,
        streamId,
        "",
        targetPort,
        this.options.streamTimeoutMs || 15000
      );
    }


    let lastErr: Error | null = null;
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      try {
        const streamId = this.allocateStreamId();
        const circuit = await this.circuitPool.getCircuit(targetPort);
        return await CircuitStream.open(
          circuit,
          streamId,
          targetHost,
          targetPort,
          this.options.streamTimeoutMs || 15000
        );
      } catch (err: any) {
        lastErr = err;
        if (attempt < maxRetries) {
          await new Promise((r) => setTimeout(r, 200 * attempt));
        }
      }
    }

    throw lastErr || new TorError(`Failed to establish stream to ${targetHost}:${targetPort}`);
  }

  /**
   * Drop-in replacement for fetch() sending HTTP/1.1 requests through the Tor network.
   * @param urlStr Absolute HTTP or .onion URL
   * @param init Standard RequestInit options (method, headers, body)
   * @returns HTTP response object
   */
  async fetch(urlStr: string, init: RequestInit = {}): Promise<TorHttpResponse> {
    const url = new URL(urlStr);
    if (url.protocol === "https:") {
      throw new TorError("HTTPS over Tor fetch is not supported because it requires a native TLS handshake over the Tor stream. Use HTTP for .onion sites, or use the CONNECT proxy server for clearnet HTTPS.");
    }
    const port = url.port ? parseInt(url.port, 10) : 80;
    const stream = await this.connectStream(url.hostname, port);

    return await TorHttpClient.request(stream, urlStr, init);
  }

  /**
   * Anonymous DNS resolution over Tor using RELAY_RESOLVE cells.
   * @param hostname Domain name to resolve
   * @returns List of resolved DNS records
   */
  async resolve(hostname: string): Promise<DnsAnswer[]> {
    const circuit = await this.circuitPool.getCircuit(53);
    const streamId = this.allocateStreamId();
    return await TorDnsResolver.resolve(circuit, hostname, streamId);
  }

  /**
   * Start an embedded local SOCKS5 proxy server.
   * @param options Port and host configuration
   * @returns Bound host and port
   */
  async createSocksServer(options: SocksServerOptions = {}): Promise<{ host: string; port: number }> {
    if (!this.socksServer) {
      this.socksServer = new TorSocksServer(this);
    }
    return await this.socksServer.listen(options);
  }

  /**
   * Start an embedded local HTTP / HTTPS CONNECT forward proxy server.
   * @param options Port and host configuration
   * @returns Bound host and port
   */
  async createHttpProxyServer(options: HttpProxyServerOptions = {}): Promise<{ host: string; port: number }> {
    if (!this.httpProxyServer) {
      this.httpProxyServer = new TorHttpProxyServer(this);
    }
    return await this.httpProxyServer.listen(options);
  }

  /**
   * Internal stream ID allocator.
   * @internal
   */
  private allocateStreamId(): number {
    const id = this.nextStreamId;
    this.nextStreamId = (this.nextStreamId % 65535) + 1;
    return id;
  }

  /**
   * Shutdown all circuits and proxy servers.
   */
  async close(): Promise<void> {
    if (this.socksServer) {
      this.socksServer.stop();
      this.socksServer = null;
    }
    if (this.httpProxyServer) {
      this.httpProxyServer.stop();
      this.httpProxyServer = null;
    }
    await this.circuitPool.closeAll();
  }
}

/**
 * Convenience helper to immediately start a standalone SOCKS5 proxy server.
 * @param options Server and Tor client options
 * @returns Client instance, bound host, and bound port
 */
export async function startSocksProxy(
  options: SocksServerOptions & TorClientOptions = {}
): Promise<{ client: TorClient; host: string; port: number }> {
  const client = new TorClient(options);
  const { host, port } = await client.createSocksServer(options);
  return { client, host, port };
}

/**
 * Convenience helper to immediately start a standalone HTTP / HTTPS CONNECT forward proxy.
 * @param options Server and Tor client options
 * @returns Client instance, bound host, and bound port
 */
export async function startHttpProxy(
  options: HttpProxyServerOptions & TorClientOptions = {}
): Promise<{ client: TorClient; host: string; port: number }> {
  const client = new TorClient(options);
  const { host, port } = await client.createHttpProxyServer(options);
  return { client, host, port };
}
