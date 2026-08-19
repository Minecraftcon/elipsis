/**
 * @module
 * Embedded SOCKS5 / SOCKS4a Proxy Server.
 * Enables local applications and microservices to route traffic through the in-process Tor client.
 */
import { TorClient } from "./tor_client.ts";
import { BufferReader, BufferWriter } from "../common/buffer_reader.ts";
import { logger } from "../common/logger.ts";

/**
 * Options for configuring the embedded SOCKS5 proxy server.
 */
export interface SocksServerOptions {
  /** Local port to bind the proxy server (default: 9250) */
  port?: number;
  /** Local host / IP to bind (default: 127.0.0.1) */
  host?: string;
}

/**
 * Embedded SOCKS5 proxy server bridging local TCP socket clients to Tor circuits.
 */
export class TorSocksServer {
  private client: TorClient;
  private server: any = null;
  private running = false;

  /**
   * Constructs a new TorSocksServer.
   * @param client Underlying TorClient instance
   */
  constructor(client: TorClient) {
    this.client = client;
  }

  /**
   * Start listening for SOCKS5 connections.
   * @param options Port and host options
   * @returns Bound host and port
   */
  async listen(options: SocksServerOptions = {}): Promise<{ host: string; port: number }> {
    const port = options.port || 9250;
    const host = options.host || "127.0.0.1";

    if (typeof (globalThis as any).Deno !== "undefined" && typeof (globalThis as any).Deno.listen === "function") {
      const listener = (globalThis as any).Deno.listen({ port, hostname: host });
      this.server = listener;
      this.running = true;

      (async () => {
        for await (const conn of listener) {
          this.handleDenoConnection(conn).catch(() => {});
        }
      })();

      logger.info("PROXY", `SOCKS5 Proxy Server listening on socks5://${host}:${port}`);
      return { host, port };
    }

    // Node.js net.createServer fallback
    const net = await import("node:net");
    return new Promise((resolve) => {
      const server = net.createServer((socket) => {
        this.handleNodeSocket(socket).catch(() => {});
      });

      this.server = server;
      server.listen(port, host, () => {
        this.running = true;
        logger.info("PROXY", `SOCKS5 Proxy Server listening on socks5://${host}:${port}`);
        resolve({ host, port });
      });
    });
  }

  /**
   * Handles incoming Deno TCP socket connections.
   * @internal
   */
  private async handleDenoConnection(conn: any): Promise<void> {
    try {
      const buf = new Uint8Array(2048);
      const n = await conn.read(buf);
      if (!n || n < 3) {
        conn.close();
        return;
      }

      // SOCKS5 greeting: VER 0x05
      if (buf[0] === 0x05) {
        logger.debug("PROXY", "Incoming SOCKS5 client greeting. Responding: No Authentication (0x05 0x00)");
        // Send No Auth Required: 0x05 0x00
        await conn.write(new Uint8Array([0x05, 0x00]));

        // Read connection request
        const reqLen = await conn.read(buf);
        if (!reqLen || reqLen < 4 || buf[1] !== 0x01) {
          conn.close();
          return;
        }

        const reader = new BufferReader(buf.subarray(0, reqLen));
        reader.readUint8(); // VER
        const cmd = reader.readUint8(); // CMD: 1 = CONNECT
        reader.readUint8(); // RSV
        const atyp = reader.readUint8(); // ATYP

        let targetHost = "";
        if (atyp === 0x01) {
          // IPv4
          const ipBytes = reader.readBytes(4);
          targetHost = `${ipBytes[0]}.${ipBytes[1]}.${ipBytes[2]}.${ipBytes[3]}`;
        } else if (atyp === 0x03) {
          // Domain
          const domainLen = reader.readUint8();
          targetHost = reader.readString(domainLen);
        } else {
          // Unsupported address type
          await conn.write(new Uint8Array([0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
          conn.close();
          return;
        }

        const targetPort = reader.readUint16();
        logger.info("PROXY", `► SOCKS5 CONNECT Request: ${targetHost}:${targetPort}`);
        logger.mechanism("SOCKS5 Stream Bridge", `Routing target ${targetHost}:${targetPort} through pure-TS Tor client`);

        // Connect directly via pure TypeScript Tor client
        let stream: any;
        try {
          stream = await this.client.connectStream(targetHost, targetPort);
        } catch (streamErr: any) {
          logger.warn("PROXY", `Failed to connect stream to ${targetHost}:${targetPort}: ${streamErr.message}`);
          try {
            // SOCKS5 General Failure: 0x05 0x01
            await conn.write(new Uint8Array([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            conn.close();
          } catch (_c) {}
          return;
        }

        // Send SOCKS5 Success response: 0x05 0x00 (Success) 0x00 0x01 0 0 0 0 0 0
        await conn.write(new Uint8Array([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
        logger.debug("PROXY", `✓ Sent SOCKS5 SUCCESS (0x00) for ${targetHost}:${targetPort}`);

        // Pipe bidirectional data — pipeFromStream uses burst-drain to coalesce
        // multiple queued Tor cells into a single conn.write() per TCP burst,
        // reducing per-cell await overhead from O(N) awaits → O(bursts) awaits.
        let totalSent = 0;
        let totalRecv = 0;

        const pipeToStream = async () => {
          const chunk = new Uint8Array(16384);
          while (true) {
            const bytes = await conn.read(chunk);
            if (!bytes || bytes === 0) break;
            totalSent += bytes;
            logger.debug("PROXY-TRACE", `Chromium sent ${bytes} bytes to ${targetHost}`);
            await stream.write(chunk.subarray(0, bytes));
          }
          logger.debug("PROXY-TRACE", `Chromium closed write stream to ${targetHost}`);
          await stream.close();
        };

        const pipeFromStream = async () => {
          while (true) {
            // Fast path: drain everything already queued (no await cost)
            const burst = (stream as any).readAllQueued?.() as Uint8Array | null | undefined;

            if (burst !== undefined) {
              // readAllQueued supported
              if (burst === null) break; // stream closed, queue empty
              if (burst.length > 0) {
                totalRecv += burst.length;
                await conn.write(burst);
                continue; // keep draining without awaiting
              }
            }

            // Queue empty (burst.length === 0) or readAllQueued not available —
            // fall back to a single awaited read()
            const data = await stream.read();
            if (!data || data.length === 0) break;
            totalRecv += data.length;
            logger.debug("PROXY-TRACE", `Tor received ${data.length} bytes from ${targetHost}`);

            // Before writing this chunk, drain anything else that arrived
            // while we were awaiting, to batch into one conn.write() call.
            if ((stream as any).readAllQueued) {
              const extra = (stream as any).readAllQueued() as Uint8Array | null;
              if (extra && extra.length > 0) {
                const merged = new Uint8Array(data.length + extra.length);
                merged.set(data, 0);
                merged.set(extra, data.length);
                totalRecv += extra.length;
                logger.debug("PROXY-TRACE", `Tor received extra ${extra.length} bytes (merged) from ${targetHost}`);
                await conn.write(merged);
              } else {
                await conn.write(data);
              }
            } else {
              await conn.write(data);
            }
          }
          logger.debug("PROXY-TRACE", `Tor stream closed for ${targetHost}`);
          conn.close();
        };

        await Promise.allSettled([pipeToStream(), pipeFromStream()]);
        logger.debug("PROXY", `Stream closed for ${targetHost}:${targetPort} (Sent: ${totalSent} B, Received: ${totalRecv} B)`);
      }
    } catch (_e) {
      logger.error("PROXY", `SOCKS5 connection error:`, _e);
      try {
        conn.close();
      } catch (_c) {}
    }
  }

  /**
   * Handles incoming Node.js net.Socket connections.
   * @internal
   */
  private async handleNodeSocket(socket: any): Promise<void> {
    socket.once("data", (greeting: Buffer) => {
      if (greeting[0] === 0x05) {
        socket.write(Buffer.from([0x05, 0x00])); // No auth

        socket.once("data", async (req: Buffer) => {
          try {
            const reader = new BufferReader(new Uint8Array(req));
            reader.readUint8(); // VER
            const cmd = reader.readUint8();
            reader.readUint8(); // RSV
            const atyp = reader.readUint8();

            let targetHost = "";
            if (atyp === 0x01) {
              const ipBytes = reader.readBytes(4);
              targetHost = `${ipBytes[0]}.${ipBytes[1]}.${ipBytes[2]}.${ipBytes[3]}`;
            } else if (atyp === 0x03) {
              const domainLen = reader.readUint8();
              targetHost = reader.readString(domainLen);
            }

            const targetPort = reader.readUint16();
            const stream = await this.client.connectStream(targetHost, targetPort);

            socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));

            socket.on("data", (data: Buffer) => {
              stream.write(new Uint8Array(data)).catch(() => {});
            });

            socket.on("close", () => {
              stream.close().catch(() => {});
            });

            (async () => {
              while (true) {
                const chunk = await stream.read();
                if (!chunk || chunk.length === 0) break;
                socket.write(Buffer.from(chunk));
              }
              socket.end();
            })();
          } catch (_e) {
            socket.write(Buffer.from([0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            socket.end();
          }
        });
      }
    });
  }

  /**
   * Stop the SOCKS proxy server.
   */
  stop(): void {
    if (this.server) {
      try {
        if (typeof this.server.close === "function") {
          this.server.close();
        }
      } catch (_e) {}
    }
    this.running = false;
  }
}
