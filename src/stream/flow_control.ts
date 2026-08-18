/**
 * Stream flow control window tracking (tor-spec Section 7.3).
 */
import { INITIAL_STREAM_WINDOW, STREAM_WINDOW_INCREMENT } from "../circuit/sendme.ts";

export class StreamFlowControl {
  private packageWindow = INITIAL_STREAM_WINDOW;
  private deliverWindow = INITIAL_STREAM_WINDOW;
  private cellsReceivedSinceSendme = 0;

  decrementPackageWindow(): void {
    this.packageWindow -= 1;
  }

  incrementPackageWindow(): void {
    this.packageWindow += STREAM_WINDOW_INCREMENT;
  }

  onCellReceived(): boolean {
    this.deliverWindow -= 1;
    this.cellsReceivedSinceSendme += 1;

    if (this.cellsReceivedSinceSendme >= STREAM_WINDOW_INCREMENT) {
      this.cellsReceivedSinceSendme = 0;
      this.deliverWindow += STREAM_WINDOW_INCREMENT;
      return true; // Send RELAY_SENDME for this stream
    }

    return false;
  }

  get canSend(): boolean {
    return this.packageWindow > 0;
  }
}
