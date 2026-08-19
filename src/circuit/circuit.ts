/**
 * Tor Circuit manager handling multi-hop onion routing, stream multiplexing, and lifecycle.
 */
import { TorLinkConnection } from "../transport/link.ts";
import { Hop } from "./hop.ts";
import { CellCommand, DestroyReason, RelayCommand } from "../protocol/constants.ts";
import {
  encryptRelayPayload,
  packageRelayPayload,
  peelRelayPayload,
  type RelayCell,
} from "../protocol/relay_cell.ts";
import { encodeSendmeV1, CircuitFlowControl } from "./sendme.ts";
import { CircuitError, TorProtocolError } from "../common/errors.ts";
import { TorCell } from "../protocol/cell.ts";
import { logger } from "../common/logger.ts";

/**
 * Tor Circuit manager handling multi-hop onion routing, stream multiplexing, and lifecycle.
 */
export class TorCircuit {
  /** Circuit identifier allocated on the Link */
  public readonly circuitId: number;
  /** Underlying TLS link connection */
  public readonly link: TorLinkConnection;
  /** List of cryptographic hops established in this circuit */
  public readonly hops: Hop[] = [];
  /** Optional listener for raw circuit control cells (e.g. CREATED2) */
  public controlListener: ((cell: TorCell) => void) | null = null;
  private relayEarlyCount = 0;
  private closed = false;
  private flowControl = new CircuitFlowControl();
  private streamListeners: Map<number, (cell: RelayCell) => void> = new Map();
  private createdAt = Date.now();
  private dirtyAt: number | null = null;

  /**
   * Constructs a new TorCircuit instance.
   * @param circuitId Unique circuit ID
   * @param link Associated link connection
   */
  constructor(circuitId: number, link: TorLinkConnection) {
    this.circuitId = circuitId;
    this.link = link;
    this.link.registerCircuit(this.circuitId, (cell) => this.handleIncomingCell(cell));
  }

  /** Whether the circuit or link is closed */
  get isClosed(): boolean {
    return this.closed || this.link.isClosed;
  }

  /** Number of hops currently attached to this circuit */
  get hopCount(): number {
    return this.hops.length;
  }

  /** Circuit age in milliseconds */
  get ageMs(): number {
    return Date.now() - this.createdAt;
  }

  /** Whether circuit has exceeded maximum clean reuse duration */
  get isDirty(): boolean {
    return this.dirtyAt !== null && Date.now() - this.dirtyAt > 10 * 60 * 1000; // 10 min Tor dirty cutoff
  }

  /** Mark circuit as used to initiate dirty cutoff timer */
  markDirty(): void {
    if (!this.dirtyAt) {
      this.dirtyAt = Date.now();
    }
  }

  /**
   * Append a newly negotiated hop to the circuit.
   * @param hop Established hop keys
   */
  addHop(hop: Hop): void {
    this.hops.push(hop);
  }

  /**
   * Send a relay cell to a specific hop (default is the last hop / exit).
   * @param command Relay cell command
   * @param streamId Associated stream ID (or 0 for control)
   * @param data Payload bytes
   * @param targetHopIndex Optional target hop index
   * @param forceRelayEarly Whether to send as RELAY_EARLY
   */
  private sendLock: Promise<void> = Promise.resolve();

  /**
   * Send a relay cell to a specific hop (default is the last hop / exit).
   * Atomically serialized using an async mutex to prevent AES-CTR cipher state races.
   * @param command Relay cell command
   * @param streamId Associated stream ID (or 0 for control)
   * @param data Payload bytes
   * @param targetHopIndex Optional target hop index
   * @param forceRelayEarly Whether to send as RELAY_EARLY
   */
  async sendRelayCell(
    command: RelayCommand,
    streamId: number,
    data: Uint8Array,
    targetHopIndex?: number,
    forceRelayEarly = false
  ): Promise<void> {
    const prev = this.sendLock;
    let release: () => void;
    this.sendLock = new Promise<void>((r) => (release = r));
    await prev.catch(() => {});

    try {
      if (this.isClosed) {
        throw new CircuitError("Cannot send relay cell on closed circuit", this.circuitId);
      }

      const hopIndex = targetHopIndex !== undefined ? targetHopIndex : this.hops.length - 1;
      if (hopIndex < 0 || hopIndex >= this.hops.length) {
        throw new CircuitError(`Invalid target hop index: ${hopIndex}`, this.circuitId);
      }

      const packaged = packageRelayPayload(command, streamId, data, this.hops[hopIndex]);
      const encrypted = encryptRelayPayload(packaged, hopIndex, this.hops);

      // Determine if we should use RELAY_EARLY (max 8 per circuit, required for circuit extension)
      let cellCommand = CellCommand.RELAY;
      if (forceRelayEarly && this.relayEarlyCount < 8) {
        cellCommand = CellCommand.RELAY_EARLY;
        this.relayEarlyCount += 1;
      }

      // Only DATA cells consume the circuit package window (tor-spec §7.3).
      // BEGIN, END, CONNECTED, SENDME are control cells and must NOT deplete it.
      if (command === RelayCommand.DATA) {
        this.flowControl.decrementPackageWindow();
      }

      await this.link.sendCell({
        circuitId: this.circuitId,
        command: cellCommand,
        payload: encrypted,
      });
    } finally {
      release!();
    }
  }

  /**
   * Dispatches and decrypts incoming cells received from link.
   * @internal
   */
  private handleIncomingCell(cell: TorCell): void {
    if (this.controlListener) {
      this.controlListener(cell);
    }

    if (cell.command === CellCommand.DESTROY) {
      this.close();
      return;
    }

    if (cell.command !== CellCommand.RELAY && cell.command !== CellCommand.RELAY_EARLY) {
      return;
    }

    let hopIndex: number;
    let relayCell: RelayCell;
    let digestTag: Uint8Array;

    try {
      const peeled = peelRelayPayload(cell.payload, this.hops);
      hopIndex = peeled.hopIndex;
      relayCell = peeled.relayCell;
      digestTag = peeled.digestTag;
    } catch (e) {
      // Drop unrecognized cells with a warning — do NOT destroy the circuit.
      // A single bad/unexpected cell (e.g. INTRODUCE_ACK arriving on RP circuit
      // before our stream listener is registered) must not kill a live HS connection.
      logger.warn("CIRCUIT", `Dropping unrecognized relay cell on circuit 0x${this.circuitId.toString(16)}: ${(e as Error).message}`);
      return;
    }

    // Handle circuit-level SENDME — only for DATA cells at circuit window
    if (relayCell.command === RelayCommand.SENDME && relayCell.streamId === 0) {
      this.flowControl.incrementPackageWindow();
      return;
    }

    // Only count RELAY_DATA cells against the circuit deliver window
    // (CONNECTED, END, SENDME cells do NOT consume window slots per tor-spec)
    if (relayCell.command === RelayCommand.DATA) {
      const { needSendme, digestTag: sendmeTag } = this.flowControl.onCellReceived(digestTag);
      if (needSendme) {
        const sendmePayload = sendmeTag ? encodeSendmeV1(sendmeTag) : new Uint8Array(0);
        this.sendRelayCell(RelayCommand.SENDME, 0, sendmePayload, hopIndex).catch(() => {});
      }
    }

    // Dispatch to stream listener
    const streamListener = this.streamListeners.get(relayCell.streamId);
    if (streamListener) {
      streamListener(relayCell);
    } else if (relayCell.streamId !== 0) {
      logger.debug("CIRCUIT", `No listener for stream ${relayCell.streamId} on circuit 0x${this.circuitId.toString(16)} (cmd=${relayCell.command})`);
    }
  }

  /**
   * Register a stream callback listener for cells with matching stream ID.
   * @param streamId Stream ID
   * @param listener Callback handler
   */
  registerStream(streamId: number, listener: (cell: RelayCell) => void): void {
    this.streamListeners.set(streamId, listener);
  }

  /**
   * Unregister stream callback listener.
   * @param streamId Stream ID
   */
  unregisterStream(streamId: number): void {
    this.streamListeners.delete(streamId);
  }

  /**
   * Teardown the circuit gracefully by sending a DESTROY cell.
   * @param reason Destroy reason code
   */
  async destroy(reason: DestroyReason = DestroyReason.REQUESTED): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      try {
        const payload = new Uint8Array([reason]);
        await this.link.sendCell({
          circuitId: this.circuitId,
          command: CellCommand.DESTROY,
          payload,
        });
      } catch (_e) {
        // Ignore send errors during teardown
      } finally {
        this.link.unregisterCircuit(this.circuitId);
        this.notifyStreamListenersCircuitClosed();
      }
    }
  }

  /**
   * Immediately close the circuit and unregister from link.
   */
  close(): void {
    this.closed = true;
    this.link.unregisterCircuit(this.circuitId);
    this.notifyStreamListenersCircuitClosed();
  }

  private notifyStreamListenersCircuitClosed(): void {
    const endCell: RelayCell = {
      command: RelayCommand.END, // 3
      streamId: 0,
      data: new Uint8Array([0x06]), // DESTROY_CHANNEL_CLOSED
    };
    for (const [streamId, listener] of this.streamListeners.entries()) {
      if (streamId !== 0) { // Don't send END to orchestrator rendezvous listener
        endCell.streamId = streamId;
        listener(endCell);
      } else {
        // For stream 0 (orchestrator waiting for RENDEZVOUS2), we shouldn't send END
        // Instead we could send a synthetic DESTROY cell if orchestrator listens for it.
        // Wait, stream 0 doesn't process END. Let's just leave it, orchestrator relies on timeouts for now.
      }
    }
  }
}
