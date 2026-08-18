/**
 * @module
 * HTTP / HTTPS CONNECT Forward Proxy Server.
 * Allows standard HTTP_PROXY / HTTPS_PROXY clients, browsers, and curl to route through Tor.
 */
import { TorClient } from "./tor_client.ts";
import { BufferReader } from "../common/buffer_reader.ts";

/**
 * Options for configuring the embedded HTTP / HTTPS CONNECT forward proxy.
 */
export interface HttpProxyServerOptions {
  /** Local port to bind the HTTP proxy server (default: 8080) */
  port?: number;
  /** Local host / IP to bind (default: 127.0.0.1) */
  host?: string;
  /** Optional callback triggered on incoming CONNECT request */
  onConnect?: (target: string) => void;
}

/**
 * Embedded HTTP / HTTPS CONNECT forward proxy server.
 */
export class TorHttpProxyServer {
  private client: TorClient;
  private server: any = null;
  private running = false;

  /**
   * Constructs a new TorHttpProxyServer.
   * @param client Underlying TorClient instance
   */
  constructor(client: TorClient) {
    this.client = client;
  }

  /**
   * Start the HTTP / HTTPS CONNECT forward proxy server.
   * @param options Port and host options
   * @returns Bound host and port
   */
  async listen(options: HttpProxyServerOptions = {}): Promise<{ host: string; port: number }> {
    const port = options.port || 8080;
    const host = options.host || "127.0.0.1";

    if (typeof (globalThis as any).Deno !== "undefined" && typeof (globalThis as any).Deno.listen === "function") {
      const listener = (globalThis as any).Deno.listen({ port, hostname: host });
      this.server = listener;
      this.running = true;

      (async () => {
        for await (const conn of listener) {
          this.handleDenoConnection(conn, options).catch(() => {});
        }
      })();

      return { host, port };
    }

    // Node.js fallback
    const net = await import("node:net");
    return new Promise((resolve) => {
      const server = net.createServer((socket) => {
        this.handleNodeSocket(socket, options).catch(() => {});
      });

      this.server = server;
      server.listen(port, host, () => {
        this.running = true;
        resolve({ host, port });
      });
    });
  }

  /**
   * Handles incoming Deno HTTP proxy connections.
   * @internal
   */
  private async handleDenoConnection(conn: any, options: HttpProxyServerOptions): Promise<void> {
    try {
      const buf = new Uint8Array(4096);
      const n = await conn.read(buf);
      if (!n || n === 0) {
        conn.close();
        return;
      }

      const reqStr = new TextDecoder().decode(buf.subarray(0, n));
      const firstLine = reqStr.split("\r\n")[0];
      const parts = firstLine.split(" ");
      const method = parts[0];
      const target = parts[1];

      if (options.onConnect) {
        options.onConnect(target);
      }

      if (method === "CONNECT") {
        // HTTPS Tunneling via CONNECT host:port HTTP/1.1
        const [targetHost, targetPortStr] = target.split(":");
        const targetPort = parseInt(targetPortStr || "443", 10);

        const stream = await this.client.connectStream(targetHost, targetPort);

        // Send 200 Connection Established
        await conn.write(new TextEncoder().encode("HTTP/1.1 200 Connection Established\r\n\r\n"));

        // Pipe bidirectional data
        const pipeToStream = async () => {
          const chunk = new Uint8Array(4096);
          while (true) {
            const bytes = await conn.read(chunk);
            if (!bytes || bytes === 0) break;
            await stream.write(chunk.subarray(0, bytes));
          }
          await stream.close();
        };

        const pipeFromStream = async () => {
          while (true) {
            const data = await stream.read();
            if (!data || data.length === 0) break;
            await conn.write(data);
          }
          conn.close();
        };

        await Promise.allSettled([pipeToStream(), pipeFromStream()]);
      } else {
        // Plain HTTP forward proxying (e.g. GET http://example.onion/path HTTP/1.1)
        const url = new URL(target.startsWith("http") ? target : `http://${target}`);
        const targetPort = url.port ? parseInt(url.port, 10) : 80;
        const stream = await this.client.connectStream(url.hostname, targetPort);

        // Rewrite proxy absolute-URI to origin-form (e.g. GET /path HTTP/1.1)
        const path = (url.pathname || "/") + (url.search || "");
        const version = parts[2] || "HTTP/1.1";
        const rewrittenFirstLine = `${method} ${path} ${version}`;
        const restOfRequest = reqStr.substring(firstLine.length);
        const rewrittenRequest = new TextEncoder().encode(rewrittenFirstLine + restOfRequest);

        const pipeToStream = async () => {
          await stream.write(rewrittenRequest);
          const chunk = new Uint8Array(4096);
          while (true) {
            const bytes = await conn.read(chunk);
            if (!bytes || bytes === 0) break;
            await stream.write(chunk.subarray(0, bytes));
          }
          await stream.close();
        };

        const pipeFromStream = async () => {
          while (true) {
            const data = await stream.read();
            if (!data || data.length === 0) break;
            await conn.write(data);
          }
          conn.close();
        };

        await Promise.allSettled([pipeToStream(), pipeFromStream()]);
      }
    } catch (_e) {
      try {
        conn.close();
      } catch (_c) {}
    }
  }

  /**
   * Handles incoming Node.js HTTP proxy sockets.
   * @internal
   */
  private async handleNodeSocket(socket: any, options: HttpProxyServerOptions): Promise<void> {
    socket.once("data", async (chunk: Buffer) => {
      try {
        const reqStr = chunk.toString("utf8");
        const firstLine = reqStr.split("\r\n")[0];
        const parts = firstLine.split(" ");
        const method = parts[0];
        const target = parts[1];

        if (options.onConnect) {
          options.onConnect(target);
        }

        if (method === "CONNECT") {
          const [targetHost, targetPortStr] = target.split(":");
          const targetPort = parseInt(targetPortStr || "443", 10);

          const stream = await this.client.connectStream(targetHost, targetPort);

          socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");

          socket.on("data", (data: Buffer) => {
            stream.write(new Uint8Array(data)).catch(() => {});
          });

          socket.on("close", () => {
            stream.close().catch(() => {});
          });

          (async () => {
            while (true) {
              const resData = await stream.read();
              if (!resData || resData.length === 0) break;
              socket.write(Buffer.from(resData));
            }
            socket.end();
          })();
        } else {
          const url = new URL(target.startsWith("http") ? target : `http://${target}`);
          const targetPort = url.port ? parseInt(url.port, 10) : 80;
          const stream = await this.client.connectStream(url.hostname, targetPort);

          // Rewrite request line to origin-form
          const path = (url.pathname || "/") + (url.search || "");
          const version = parts[2] || "HTTP/1.1";
          const rewrittenFirstLine = `${method} ${path} ${version}`;
          const restOfRequest = reqStr.substring(firstLine.length);
          const rewrittenRequest = Buffer.from(rewrittenFirstLine + restOfRequest, "utf8");

          await stream.write(new Uint8Array(rewrittenRequest));

          socket.on("data", (data: Buffer) => {
            stream.write(new Uint8Array(data)).catch(() => {});
          });

          socket.on("close", () => {
            stream.close().catch(() => {});
          });

          (async () => {
            while (true) {
              const resData = await stream.read();
              if (!resData || resData.length === 0) break;
              socket.write(Buffer.from(resData));
            }
            socket.end();
          })();
        }
      } catch (_e) {
        socket.write("HTTP/1.1 502 Bad Gateway\r\n\r\n");
        socket.end();
      }
    });
  }

  /**
   * Stop the HTTP proxy server.
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
