/**
 * Tor Stream multiplexer for data transmission over circuits.
 * Implements Tor Protocol Specification Section 6.2.
 */
import { TorCircuit } from "../circuit/circuit.ts";
import { MAX_RELAY_DATA_LEN, RelayCommand } from "../protocol/constants.ts";
import { StreamFlowControl } from "./flow_control.ts";
import { StreamError } from "../common/errors.ts";
import { TorStream } from "../common/types.ts";

export class CircuitStream implements TorStream {
  public readonly streamId: number;
  public readonly circuit: TorCircuit;
  private flowControl = new StreamFlowControl();
  private incomingDataQueue: Uint8Array[] = [];
  private dataWaiters: ((data: Uint8Array | null) => void)[] = [];
  private closed = false;

  constructor(streamId: number, circuit: TorCircuit) {
    this.streamId = streamId;
    this.circuit = circuit;

    this.circuit.registerStream(this.streamId, (relayCell) => {
      this.handleIncomingRelayCell(relayCell);
    });
  }

  get isClosed(): boolean {
    return this.closed || this.circuit.isClosed;
  }

  /**
   * Connect stream to remote host:port via RELAY_BEGIN.
   */
  static async open(
    circuit: TorCircuit,
    streamId: number,
    targetHost: string,
    targetPort: number,
    timeoutMs = 15000
  ): Promise<CircuitStream> {
    const stream = new CircuitStream(streamId, circuit);

    const connectPromise = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        stream.close();
        reject(new StreamError(`Timeout connecting stream to ${targetHost}:${targetPort}`, streamId));
      }, timeoutMs);

      circuit.registerStream(streamId, (cell) => {
        if (cell.command === RelayCommand.CONNECTED) {
          clearTimeout(timer);
          // Restore permanent data cell listener
          circuit.registerStream(streamId, (dataCell) => stream.handleIncomingRelayCell(dataCell));
          resolve();
        } else if (cell.command === RelayCommand.END) {
          clearTimeout(timer);
          stream.close();
          const reason = cell.data.length > 0 ? cell.data[0] : 0;
          reject(new StreamError(`Stream connection refused with reason ${reason}`, streamId));
        }
      });
    });

    const targetPayload = new TextEncoder().encode(`${targetHost}:${targetPort}\0`);
    await circuit.sendRelayCell(RelayCommand.BEGIN, streamId, targetPayload);

    await connectPromise;
    return stream;
  }

  /**
   * Connect an internal directory stream via RELAY_BEGIN_DIR.
   */
  static async openDir(
    circuit: TorCircuit,
    streamId = 1,
    timeoutMs = 15000
  ): Promise<CircuitStream> {
    const stream = new CircuitStream(streamId, circuit);

    const connectPromise = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        stream.close();
        reject(new StreamError("Timeout opening BEGIN_DIR directory stream", streamId));
      }, timeoutMs);

      circuit.registerStream(streamId, (cell) => {
        if (cell.command === RelayCommand.CONNECTED) {
          clearTimeout(timer);
          circuit.registerStream(streamId, (dataCell) => stream.handleIncomingRelayCell(dataCell));
          resolve();
        } else if (cell.command === RelayCommand.END) {
          clearTimeout(timer);
          stream.close();
          const reason = cell.data.length > 0 ? cell.data[0] : 0;
          reject(new StreamError(`BEGIN_DIR directory stream refused with reason ${reason}`, streamId));
        }
      });
    });

    await circuit.sendRelayCell(RelayCommand.BEGIN_DIR, streamId, new Uint8Array(0));
    await connectPromise;
    return stream;
  }

  private handleIncomingRelayCell(cell: { command: RelayCommand; data: Uint8Array }): void {
    if (cell.command === RelayCommand.DATA) {
      if (this.flowControl.onCellReceived()) {
        this.circuit.sendRelayCell(RelayCommand.SENDME, this.streamId, new Uint8Array(0)).catch(() => {});
      }

      if (this.dataWaiters.length > 0) {
        const waiter = this.dataWaiters.shift()!;
        waiter(cell.data);
      } else {
        this.incomingDataQueue.push(cell.data);
      }
    } else if (cell.command === RelayCommand.SENDME) {
      this.flowControl.incrementPackageWindow();
    } else if (cell.command === RelayCommand.END) {
      this.close();
    }
  }

  /**
   * Read the next chunk of incoming data from the stream.
   * Returns null when stream is closed.
   */
  async read(): Promise<Uint8Array | null> {
    if (this.incomingDataQueue.length > 0) {
      return this.incomingDataQueue.shift()!;
    }
    if (this.isClosed) {
      return null;
    }
    return new Promise<Uint8Array | null>((resolve) => {
      this.dataWaiters.push(resolve);
    });
  }

  /**
   * Write data chunk(s) across the Tor stream in <= 498-byte cells.
   */
  async write(data: Uint8Array): Promise<void> {
    if (this.isClosed) {
      throw new StreamError("Cannot write to closed stream", this.streamId);
    }

    let offset = 0;
    while (offset < data.length) {
      const chunkSize = Math.min(MAX_RELAY_DATA_LEN, data.length - offset);
      const chunk = data.subarray(offset, offset + chunkSize);

      this.flowControl.decrementPackageWindow();
      await this.circuit.sendRelayCell(RelayCommand.DATA, this.streamId, chunk);
      offset += chunkSize;
    }
  }

  /**
   * Close the stream gracefully.
   */
  async close(reason: number = 0x06): Promise<void> {
    if (!this.closed) {
      this.closed = true;
      try {
        await this.circuit.sendRelayCell(RelayCommand.END, this.streamId, new Uint8Array([reason]));
      } catch (_e) {
      } finally {
        this.circuit.unregisterStream(this.streamId);
        while (this.dataWaiters.length > 0) {
          this.dataWaiters.shift()!(null);
        }
      }
    }
  }
}
