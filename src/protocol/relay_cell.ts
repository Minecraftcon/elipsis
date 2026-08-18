/**
 * Tor Relay Cell packaging, multi-hop onion encryption, and peeling engine.
 * Implements Tor Protocol Specification Section 6.1 & 6.2.
 */
import { BufferReader, BufferWriter } from "../common/buffer_reader.ts";
import {
  MAX_RELAY_DATA_LEN,
  RELAY_HEADER_LEN,
  RELAY_PAYLOAD_LEN,
  RelayCommand,
} from "./constants.ts";
import { TorDigest } from "../crypto/digest.ts";
import { TorStreamCipher } from "../crypto/cipher.ts";
import { constantTimeEqual } from "../crypto/utils.ts";
import { TorProtocolError } from "../common/errors.ts";

/**
 * Structured decoded Relay Cell payload.
 */
export interface RelayCell {
  /** Relay command identifier */
  command: RelayCommand;
  /** Associated stream ID on the circuit */
  streamId: number;
  /** Unencrypted payload bytes */
  data: Uint8Array;
}

/**
 * Cryptographic state interface for a single circuit hop.
 */
export interface CircuitHopCrypto {
  /** Forward running digest */
  forwardDigest: TorDigest;
  /** Backward running digest */
  backwardDigest: TorDigest;
  /** Forward AES-CTR stream cipher */
  forwardCipher: TorStreamCipher;
  /** Backward AES-CTR stream cipher */
  backwardCipher: TorStreamCipher;
}

/**
 * Package unencrypted relay data into a raw 509-byte relay payload.
 */
export function packageRelayPayload(
  command: RelayCommand,
  streamId: number,
  data: Uint8Array,
  hopCrypto: CircuitHopCrypto
): Uint8Array {
  if (data.length > MAX_RELAY_DATA_LEN) {
    throw new TorProtocolError(
      `Relay cell data length ${data.length} exceeds maximum ${MAX_RELAY_DATA_LEN}`
    );
  }

  const payload = new Uint8Array(RELAY_PAYLOAD_LEN);
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength);

  // 1. Set Header
  view.setUint8(0, command);
  view.setUint16(1, 0, false); // Recognized = 0
  view.setUint16(3, streamId, false); // Stream ID
  view.setUint32(5, 0, false); // Digest = 0 initially
  view.setUint16(9, data.length, false); // Data Length

  // 2. Set Data
  payload.set(data, RELAY_HEADER_LEN);

  // 3. Update forward digest and write 4-byte tag into header
  const digestTag = hopCrypto.forwardDigest.updateAndGetTag(payload);
  payload.set(digestTag, 5);

  return payload;
}

/**
 * Apply multi-layer onion encryption to a 509-byte relay payload.
 * Encrypts from target hop index down to hop 0 (Guard).
 */
export function encryptRelayPayload(
  payload: Uint8Array,
  targetHopIndex: number,
  hops: CircuitHopCrypto[]
): Uint8Array {
  let current = payload;
  for (let i = targetHopIndex; i >= 0; i--) {
    current = hops[i].forwardCipher.process(current);
  }
  return current;
}

/**
 * Peel layers of encryption from an incoming 509-byte relay cell payload.
 * Returns the recognized hop index and parsed RelayCell, or null if unrecognized.
 */
export function peelRelayPayload(
  encryptedPayload: Uint8Array,
  hops: CircuitHopCrypto[]
): { hopIndex: number; relayCell: RelayCell; digestTag: Uint8Array } {
  let current = encryptedPayload;

  for (let i = 0; i < hops.length; i++) {
    current = hops[i].backwardCipher.process(current);

    // Check if cell is recognized at this hop
    const recognized = (current[1] << 8) | current[2];
    if (recognized === 0) {
      // Possible match! Verify running digest.
      const cellDigest = current.subarray(5, 9);
      const testPayload = new Uint8Array(current);
      testPayload[5] = 0;
      testPayload[6] = 0;
      testPayload[7] = 0;
      testPayload[8] = 0;

      const expectedTag = hops[i].backwardDigest.peekTag(testPayload);

      if (constantTimeEqual(cellDigest, expectedTag)) {
        // Genuine cell from hop i! Commit backward digest state and get running digest.
        const digestTag = hops[i].backwardDigest.update(testPayload);

        const command = current[0] as RelayCommand;
        const streamId = (current[3] << 8) | current[4];
        const length = (current[9] << 8) | current[10];

        if (length > MAX_RELAY_DATA_LEN) {
          throw new TorProtocolError(`Invalid relay cell data length: ${length}`);
        }

        const data = current.subarray(RELAY_HEADER_LEN, RELAY_HEADER_LEN + length);
        return {
          hopIndex: i,
          relayCell: { command, streamId, data: new Uint8Array(data) },
          digestTag,
        };
      }
    }
  }

  throw new TorProtocolError("Incoming relay cell was not recognized by any circuit hop!");
}
