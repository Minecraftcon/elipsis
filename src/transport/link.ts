/**
 * Tor Link Protocol (v4 / v5) Connection and Handshake Engine.
 * Implements tor-spec.txt Sections 3 & 4.
 */
import { BufferReader, BufferWriter } from "../common/buffer_reader.ts";
import { CellCommand, CELL_LEN } from "../protocol/constants.ts";
import { decodeCell, encodeCell, type TorCell } from "../protocol/cell.ts";
import { connectTlsSocket, type TorSocket } from "./socket.ts";
import { TorProtocolError } from "../common/errors.ts";
import { logger } from "../common/logger.ts";

export interface LinkHandshakeResult {
  negotiatedVersion: number;
  relayTime: number;
  myObservedIp?: string;
}

/**
 * Manages raw TLS Link framing and cell multiplexing over Tor Link Protocol v4/v5.
 */
export class TorLinkConnection {
  private socket: TorSocket;
  private linkVersion = 5;
  // Pre-allocated ring buffer — grows geometrically, never shrinks.
  // Eliminates per-read O(n) copy + GC churn.
  private ringBuf = new Uint8Array(65536);
  private ringHead = 0; // index of first valid byte
  private ringLen  = 0; // number of valid bytes
  private closed = false;
  private cellListeners: Map<number, (cell: TorCell) => void> = new Map();
  private defaultCellQueue: TorCell[] = [];
  private defaultCellWaiters: ((cell: TorCell) => void)[] = [];

  private constructor(socket: TorSocket) {
    this.socket = socket;
  }

  /**
   * Connect to a Tor relay and perform the complete Link Protocol v4/v5 handshake.
   * @param ip Relay IPv4 string
   * @param port Relay ORPort
   * @returns Established authenticated link connection
   */
  static async connect(ip: string, port: number): Promise<TorLinkConnection> {
    logger.debug("LINK", `Initiating TLS connection to Tor relay ${ip}:${port}...`);
    logger.mechanism("TLS Link Framing", `Establishing raw TLS socket to relay ${ip}:${port}`);
    const socket = await connectTlsSocket(ip, port);
    const link = new TorLinkConnection(socket);
    await link.performHandshake(ip);
    link.startReadLoop();
    logger.info("LINK", `✓ TLS Link Protocol v${link.version} authenticated with ${ip}:${port}`);
    return link;
  }

  /** Whether the underlying socket is closed */
  get isClosed(): boolean {
    return this.closed;
  }

  /** Negotiated link protocol version (4 or 5) */
  get version(): number {
    return this.linkVersion;
  }

  /**
   * Performs link protocol handshake with relay.
   * @internal
   */
  private async performHandshake(relayIp: string): Promise<LinkHandshakeResult> {
    logger.mechanism("Link Protocol v4/v5 Handshake", "Sending client VERSIONS cell [4, 5] (tor-spec Section 3)");
    // 1. Send client VERSIONS cell [4, 5]
    const versionsPayload = new Uint8Array([0x00, 0x04, 0x00, 0x05]);
    const clientVersionsCell: TorCell = {
      circuitId: 0,
      command: CellCommand.VERSIONS,
      payload: versionsPayload,
    };
    await this.socket.write(encodeCell(clientVersionsCell, 5));

    // 2. Read until we receive server VERSIONS cell
    const serverVersionsCell = await this.readOneCellDirect(3);
    if (serverVersionsCell.command !== CellCommand.VERSIONS) {
      throw new TorProtocolError(`Expected VERSIONS cell, got command ${serverVersionsCell.command}`);
    }

    // Parse server supported versions
    const reader = new BufferReader(serverVersionsCell.payload);
    const serverVersions: number[] = [];
    while (reader.remaining >= 2) {
      serverVersions.push(reader.readUint16());
    }

    if (serverVersions.includes(5)) {
      this.linkVersion = 5;
    } else if (serverVersions.includes(4)) {
      this.linkVersion = 4;
    } else {
      throw new TorProtocolError(`No mutually supported link version. Server offered: ${serverVersions}`);
    }

    // 3. Read CERTS, AUTH_CHALLENGE (optional), and NETINFO cells
    let netinfoCell: TorCell | null = null;
    while (!netinfoCell) {
      const cell = await this.readOneCellDirect(this.linkVersion);
      if (cell.command === CellCommand.NETINFO) {
        netinfoCell = cell;
      }
      // CERTS and AUTH_CHALLENGE can be parsed or skipped for client-only connections
    }

    // 4. Parse server NETINFO
    const netReader = new BufferReader(netinfoCell.payload);
    const relayTime = netReader.readUint32();

    // 5. Send client NETINFO cell in response
    const clientNetinfoWriter = new BufferWriter();
    const nowUnix = Math.floor(Date.now() / 1000);
    clientNetinfoWriter.writeUint32(nowUnix);

    // Other address (Relay's address as seen by client)
    const ipParts = relayIp.split(".").map((p) => parseInt(p, 10));
    if (ipParts.length === 4) {
      clientNetinfoWriter.writeUint8(0x04); // Type IPv4
      clientNetinfoWriter.writeUint8(4); // Length 4
      clientNetinfoWriter.writeBytes(new Uint8Array(ipParts));
    } else {
      clientNetinfoWriter.writeUint8(0x00); // Unknown
      clientNetinfoWriter.writeUint8(0);
    }

    // My addresses count = 0
    clientNetinfoWriter.writeUint8(0);

    const clientNetinfoCell: TorCell = {
      circuitId: 0,
      command: CellCommand.NETINFO,
      payload: clientNetinfoWriter.toUint8Array(),
    };

    await this.socket.write(encodeCell(clientNetinfoCell, this.linkVersion));

    return {
      negotiatedVersion: this.linkVersion,
      relayTime,
    };
  }

  /**
   * Append bytes into the ring buffer, growing geometrically if needed.
   * @internal
   */
  private ringAppend(src: Uint8Array, srcLen: number): void {
    const needed = this.ringLen + srcLen;
    if (needed > this.ringBuf.length) {
      // Grow to next power-of-two that fits
      let newCap = this.ringBuf.length;
      while (newCap < needed) newCap *= 2;
      const grown = new Uint8Array(newCap);
      // Compact existing data to front of new buffer
      if (this.ringLen > 0) {
        const tail = this.ringBuf.length - this.ringHead;
        if (tail >= this.ringLen) {
          grown.set(this.ringBuf.subarray(this.ringHead, this.ringHead + this.ringLen), 0);
        } else {
          grown.set(this.ringBuf.subarray(this.ringHead), 0);
          grown.set(this.ringBuf.subarray(0, this.ringLen - tail), tail);
        }
      }
      this.ringBuf = grown;
      this.ringHead = 0;
    } else if (this.ringHead + this.ringLen + srcLen > this.ringBuf.length) {
      // Compact — slide existing data to front
      if (this.ringLen > 0) {
        this.ringBuf.copyWithin(0, this.ringHead, this.ringHead + this.ringLen);
      }
      this.ringHead = 0;
    }
    // Append new bytes after existing valid data
    this.ringBuf.set(src.subarray(0, srcLen), this.ringHead + this.ringLen);
    this.ringLen += srcLen;
  }

  /** Consume N bytes from the front of the ring buffer. @internal */
  private ringConsume(n: number): void {
    this.ringHead = (this.ringHead + n) % this.ringBuf.length;
    this.ringLen -= n;
    if (this.ringLen === 0) this.ringHead = 0; // reset head for best cache locality
  }

  /** Return a view of the valid ring buffer data (always contiguous after compaction). @internal */
  private ringView(): Uint8Array {
    return this.ringBuf.subarray(this.ringHead, this.ringHead + this.ringLen);
  }

  /**
   * Read a single cell directly during the initial handshake before the main event loop starts.
   */
  private async readOneCellDirect(version: number): Promise<TorCell> {
    const chunk = new Uint8Array(16384);
    while (true) {
      const decoded = decodeCell(this.ringView(), version);
      if (decoded) {
        this.ringConsume(decoded.bytesConsumed);
        return decoded.cell;
      }

      const bytesRead = await this.socket.read(chunk);
      if (bytesRead === null || bytesRead === 0) {
        throw new TorProtocolError("Connection closed during link handshake");
      }
      this.ringAppend(chunk, bytesRead);
    }
  }

  /**
   * Background read loop dispatching incoming cells to circuit listeners.
   * Uses the pre-allocated ring buffer — no per-read allocation or O(n) copy.
   */
  private async startReadLoop(): Promise<void> {
    const chunk = new Uint8Array(16384); // 16KB read window
    try {
      while (!this.closed) {
        // Drain all fully-buffered cells before doing another socket read
        let decoded = decodeCell(this.ringView(), this.linkVersion);
        while (decoded) {
          this.ringConsume(decoded.bytesConsumed);
          this.dispatchCell(decoded.cell);
          decoded = decodeCell(this.ringView(), this.linkVersion);
        }

        const bytesRead = await this.socket.read(chunk);
        if (bytesRead === null || bytesRead === 0) {
          this.close();
          break;
        }
        this.ringAppend(chunk, bytesRead);
      }
    } catch (_e) {
      this.close();
    }
  }

  /**
   * Dispatches incoming cell to registered circuit listener.
   * @internal
   */
  private dispatchCell(cell: TorCell): void {
    const cmdName = CellCommand[cell.command] || `0x${cell.command.toString(16)}`;
    logger.trace("CELL", `◄ Incoming Cell: cmd=${cmdName} (${cell.command}), circId=0x${cell.circuitId.toString(16)}, len=${cell.payload.length}`);

    const listener = this.cellListeners.get(cell.circuitId);
    if (listener) {
      listener(cell);
    } else if (this.defaultCellWaiters.length > 0) {
      const waiter = this.defaultCellWaiters.shift()!;
      waiter(cell);
    } else {
      this.defaultCellQueue.push(cell);
    }
  }

  /**
   * Register a circuit cell listener.
   * @param circuitId Unique circuit ID
   * @param listener Cell callback handler
   */
  registerCircuit(circuitId: number, listener: (cell: TorCell) => void): void {
    logger.debug("CIRCUIT", `Registered listener for circuit 0x${circuitId.toString(16)}`);
    this.cellListeners.set(circuitId, listener);
  }

  /**
   * Unregister a circuit cell listener.
   * @param circuitId Unique circuit ID
   */
  unregisterCircuit(circuitId: number): void {
    logger.debug("CIRCUIT", `Unregistered listener for circuit 0x${circuitId.toString(16)}`);
    this.cellListeners.delete(circuitId);
  }

  /**
   * Send a Tor cell across this link.
   * @param cell Cell to transmit
   */
  async sendCell(cell: TorCell): Promise<void> {
    if (this.closed) {
      throw new TorProtocolError("Cannot send cell on closed link connection");
    }
    const cmdName = CellCommand[cell.command] || `0x${cell.command.toString(16)}`;
    logger.trace("CELL", `► Outgoing Cell: cmd=${cmdName} (${cell.command}), circId=0x${cell.circuitId.toString(16)}, len=${cell.payload.length}`);
    const encoded = encodeCell(cell, this.linkVersion);
    await this.socket.write(encoded);
  }

  /**
   * Close the link connection and underlying socket.
   */
  close(): void {
    if (!this.closed) {
      this.closed = true;
      this.socket.close();
      const destroyCell: TorCell = {
        circuitId: 0,
        command: CellCommand.DESTROY, // 4
        payload: new Uint8Array([0x06]), // CHANNEL_CLOSED
      };
      for (const [circuitId, listener] of this.cellListeners.entries()) {
        destroyCell.circuitId = circuitId;
        listener(destroyCell);
      }
      this.cellListeners.clear();
    }
  }
}
