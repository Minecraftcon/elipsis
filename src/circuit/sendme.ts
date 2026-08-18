/**
 * Tor Circuit & Stream Flow Control and Authenticated SENDME (tor-spec Section 7.3 & Proposal 289).
 */
import { BufferReader, BufferWriter } from "../common/buffer_reader.ts";

export const INITIAL_CIRCUIT_WINDOW = 1000;
export const CIRCUIT_WINDOW_INCREMENT = 100;

export const INITIAL_STREAM_WINDOW = 500;
export const STREAM_WINDOW_INCREMENT = 50;

export class CircuitFlowControl {
  private packageWindow = INITIAL_CIRCUIT_WINDOW;
  private deliverWindow = INITIAL_CIRCUIT_WINDOW;
  private cellsReceivedSinceSendme = 0;
  private lastDigestTag: Uint8Array = new Uint8Array(20);

  /**
   * Called when sending a relay cell. Decrements the package window.
   */
  decrementPackageWindow(): void {
    this.packageWindow -= 1;
  }

  /**
   * Called when receiving a SENDME cell. Increments package window.
   */
  incrementPackageWindow(): void {
    this.packageWindow += CIRCUIT_WINDOW_INCREMENT;
  }

  /**
   * Called when a relay data cell is received.
   * Returns true if a SENDME cell needs to be sent back to the hop.
   */
  onCellReceived(cellDigest?: Uint8Array): { needSendme: boolean; digestTag?: Uint8Array } {
    this.deliverWindow -= 1;
    this.cellsReceivedSinceSendme += 1;

    if (cellDigest) {
      this.lastDigestTag = cellDigest;
    }

    if (this.cellsReceivedSinceSendme >= CIRCUIT_WINDOW_INCREMENT) {
      this.cellsReceivedSinceSendme = 0;
      this.deliverWindow += CIRCUIT_WINDOW_INCREMENT;
      return { needSendme: true, digestTag: this.lastDigestTag };
    }

    return { needSendme: false };
  }

  get canSend(): boolean {
    return this.packageWindow > 0;
  }
}

/**
 * Encode an Authenticated SENDME (Version 1) cell payload.
 */
export function encodeSendmeV1(digest: Uint8Array): Uint8Array {
  const writer = new BufferWriter();
  writer.writeUint8(1); // Version 1
  writer.writeUint16(digest.length);
  writer.writeBytes(digest);
  return writer.toUint8Array();
}
