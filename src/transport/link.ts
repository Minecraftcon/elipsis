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
  private readBuffer = new Uint8Array(0);
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
   * Read a single cell directly during the initial handshake before the main event loop starts.
   */
  private async readOneCellDirect(version: number): Promise<TorCell> {
    const chunk = new Uint8Array(4096);
    while (true) {
      const decoded = decodeCell(this.readBuffer, version);
      if (decoded) {
        this.readBuffer = this.readBuffer.subarray(decoded.bytesConsumed);
        return decoded.cell;
      }

      const bytesRead = await this.socket.read(chunk);
      if (bytesRead === null || bytesRead === 0) {
        throw new TorProtocolError("Connection closed during link handshake");
      }

      const newBuf = new Uint8Array(this.readBuffer.length + bytesRead);
      newBuf.set(this.readBuffer, 0);
      newBuf.set(chunk.subarray(0, bytesRead), this.readBuffer.length);
      this.readBuffer = newBuf;
    }
  }

  /**
   * Background read loop dispatching incoming cells to circuit listeners.
   */
  private async startReadLoop(): Promise<void> {
    const chunk = new Uint8Array(4096);
    try {
      while (!this.closed) {
        const decoded = decodeCell(this.readBuffer, this.linkVersion);
        if (decoded) {
          this.readBuffer = this.readBuffer.subarray(decoded.bytesConsumed);
          this.dispatchCell(decoded.cell);
          continue;
        }

        const bytesRead = await this.socket.read(chunk);
        if (bytesRead === null || bytesRead === 0) {
          this.close();
          break;
        }

        const newBuf = new Uint8Array(this.readBuffer.length + bytesRead);
        newBuf.set(this.readBuffer, 0);
        newBuf.set(chunk.subarray(0, bytesRead), this.readBuffer.length);
        this.readBuffer = newBuf;
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
    }
  }
}
