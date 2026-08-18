/**
 * Cross-runtime TLS Socket abstraction for Deno, Supabase Edge Functions, Node.js, and Android Termux.
 * Configured with in-band Tor certificate handling (rejectUnauthorized: false), SNI, and TCP keepalive.
 */
import { TorError } from "../common/errors.ts";
import * as tls from "node:tls";

import * as net from "node:net";

/**
 * Bidirectional asynchronous byte stream socket.
 */
export interface TorSocket {
  /** Read next chunk into buffer, returns bytes read or null on EOF */
  read(buffer: Uint8Array): Promise<number | null>;
  /** Write byte buffer to socket */
  write(data: Uint8Array): Promise<void>;
  /** Close underlying socket connection */
  close(): Promise<void> | void;
}

/**
 * Connect to a Tor relay ORPort over TLS with automatic retry and mobile network resilience.
 * @param host Relay IP or hostname
 * @param port Relay ORPort (e.g. 443, 9001)
 * @param timeoutMs Handshake timeout in milliseconds
 * @param retries Maximum connection retry attempts on transient network failures (default: 3)
 * @returns Connected TorSocket instance
 */
export async function connectTlsSocket(
  host: string,
  port: number,
  timeoutMs = 10000,
  retries = 3
): Promise<TorSocket> {
  let lastError: Error | null = null;

  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await connectTlsSocketSingle(host, port, timeoutMs);
    } catch (err: any) {
      lastError = err;
      if (attempt < retries) {
        // Exponential backoff delay (250ms, 500ms, 1000ms...)
        const delayMs = Math.min(250 * Math.pow(2, attempt - 1), 2000);
        await new Promise((resolve) => setTimeout(resolve, delayMs));
      }
    }
  }

  throw new TorError(
    `TLS connection failed to ${host}:${port} after ${retries} attempts: ${lastError?.message || "Unknown error"}`
  );
}

/**
 * Internal single TLS connection attempt.
 * @internal
 */
async function connectTlsSocketSingle(
  host: string,
  port: number,
  timeoutMs: number
): Promise<TorSocket> {
  return await new Promise<TorSocket>((resolve, reject) => {
    let resolved = false;

    const isIpLiteral = net.isIP(host) !== 0;

    // Configure TLS socket with SNI for domain names and certificate bypass for in-band Tor CERTS cells
    const socket = tls.connect({
      host: host,
      port: port,
      rejectUnauthorized: false,
      ...(isIpLiteral ? {} : { servername: host }),
    });

    const timer = setTimeout(() => {
      if (!resolved) {
        socket.destroy();
        reject(new TorError(`TLS connection timeout to ${host}:${port} after ${timeoutMs}ms`));
      }
    }, timeoutMs);

    socket.on("secureConnect", () => {
      resolved = true;
      clearTimeout(timer);

      // Optimize socket for real-time onion cell packet streaming and mobile keepalive
      try {
        socket.setNoDelay(true);
        socket.setKeepAlive(true, 5000);
      } catch (_e) {
        // Ignored on platforms where unsupported
      }

      const readQueue: { buffer: Uint8Array; resolve: (n: number | null) => void }[] = [];
      const incomingChunks: Uint8Array[] = [];
      let isClosed = false;

      socket.on("data", (chunk: Buffer) => {
        const u8 = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength);
        if (readQueue.length > 0) {
          const req = readQueue.shift()!;
          const len = Math.min(req.buffer.length, u8.length);
          req.buffer.set(u8.subarray(0, len), 0);
          if (len < u8.length) {
            incomingChunks.unshift(u8.subarray(len));
          }
          req.resolve(len);
        } else {
          incomingChunks.push(u8);
        }
      });

      socket.on("end", () => {
        isClosed = true;
        while (readQueue.length > 0) {
          readQueue.shift()!.resolve(null);
        }
      });

      socket.on("error", (_e) => {
        isClosed = true;
        while (readQueue.length > 0) {
          readQueue.shift()!.resolve(null);
        }
      });

      resolve({
        async read(buffer: Uint8Array): Promise<number | null> {
          if (incomingChunks.length > 0) {
            const chunk = incomingChunks.shift()!;
            const len = Math.min(buffer.length, chunk.length);
            buffer.set(chunk.subarray(0, len), 0);
            if (len < chunk.length) {
              incomingChunks.unshift(chunk.subarray(len));
            }
            return len;
          }
          if (isClosed) return null;
          return new Promise((res) => {
            readQueue.push({ buffer, resolve: res });
          });
        },
        async write(data: Uint8Array): Promise<void> {
          if (isClosed) {
            throw new TorError("Cannot write to closed TLS socket");
          }
          return new Promise((res, rej) => {
            socket.write(Buffer.from(data), (err) => {
              if (err) rej(err);
              else res();
            });
          });
        },
        close(): void {
          isClosed = true;
          socket.destroy();
        },
      });
    });

    socket.on("error", (err) => {
      if (!resolved) {
        clearTimeout(timer);
        reject(new TorError(`TLS connection error to ${host}:${port}: ${err.message}`));
      }
    });
  });
}
