/**
 * Rendezvous circuit and Introduction Point engine for v3 Hidden Services.
 * Implements rend-spec-v3 Section 4.
 */
import { TorCircuit } from "../circuit/circuit.ts";
import { RelayCommand } from "../protocol/constants.ts";
import { randomBytes } from "../crypto/utils.ts";
import { BufferReader, BufferWriter } from "../common/buffer_reader.ts";
import { HiddenServiceError } from "../common/errors.ts";

export class RendezvousManager {
  /**
   * Establish a rendezvous point on a circuit using RELAY_ESTABLISH_RENDEZVOUS.
   * Returns the 20-byte rendezvous cookie.
   */
  static async establishRendezvous(circuit: TorCircuit): Promise<Uint8Array> {
    const cookie = randomBytes(20);

    const ackPromise = new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        circuit.unregisterStream(0);
        reject(new HiddenServiceError("Timeout waiting for RENDEZVOUS_ESTABLISHED"));
      }, 15000);

      circuit.registerStream(0, (relayCell) => {
        if (relayCell.command === RelayCommand.RENDEZVOUS_ESTABLISHED) {
          clearTimeout(timer);
          circuit.unregisterStream(0);
          resolve();
        } else if (relayCell.command === RelayCommand.END) {
          clearTimeout(timer);
          circuit.unregisterStream(0);
          reject(new HiddenServiceError("Received RELAY_END while establishing rendezvous"));
        }
      });
    });

    await circuit.sendRelayCell(RelayCommand.ESTABLISH_RENDEZVOUS, 0, cookie);
    await ackPromise;

    return cookie;
  }
}
