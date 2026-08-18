import { assertEquals, assertNotEquals } from "jsr:@std/assert";
import { CELL_LEN, CellCommand, RelayCommand } from "../src/protocol/constants.ts";
import { encodeCell, decodeCell } from "../src/protocol/cell.ts";
import {
  encryptRelayPayload,
  packageRelayPayload,
  peelRelayPayload,
  type CircuitHopCrypto,
} from "../src/protocol/relay_cell.ts";
import { TorDigest } from "../src/crypto/digest.ts";
import { TorStreamCipher } from "../src/crypto/cipher.ts";
import { randomBytes } from "../src/crypto/utils.ts";

Deno.test("fixed cell encoding and decoding", () => {
  const payload = new Uint8Array([1, 2, 3, 4, 5]);
  const cell = {
    circuitId: 0x80000001,
    command: CellCommand.CREATE2,
    payload,
  };

  const encoded = encodeCell(cell, 5);
  assertEquals(encoded.length, CELL_LEN);

  const decoded = decodeCell(encoded, 5);
  assertNotEquals(decoded, null);
  assertEquals(decoded!.cell.circuitId, 0x80000001);
  assertEquals(decoded!.cell.command, CellCommand.CREATE2);
  assertEquals(decoded!.bytesConsumed, CELL_LEN);
});

Deno.test("variable cell (VERSIONS) encoding and decoding", () => {
  const versionsPayload = new Uint8Array([0x00, 0x04, 0x00, 0x05]); // Versions 4 and 5
  const cell = {
    circuitId: 0,
    command: CellCommand.VERSIONS,
    payload: versionsPayload,
  };

  const encoded = encodeCell(cell, 5);
  assertEquals(encoded.length, 5 + 4); // 2 bytes circId + 1 byte cmd + 2 bytes len + 4 bytes payload

  const decoded = decodeCell(encoded, 5);
  assertNotEquals(decoded, null);
  assertEquals(decoded!.cell.command, CellCommand.VERSIONS);
  assertEquals(decoded!.cell.payload, versionsPayload);
});

Deno.test("3-hop multi-layer backward onion encryption and client peeling", () => {
  // Setup identical crypto states for Client and 3 Relays (Hop 0=Guard, Hop 1=Middle, Hop 2=Exit)
  const clientHops: CircuitHopCrypto[] = [];
  const relayHops: CircuitHopCrypto[] = [];

  for (let i = 0; i < 3; i++) {
    const seedF = randomBytes(20);
    const seedB = randomBytes(20);
    const keyF = randomBytes(16);
    const keyB = randomBytes(16);

    clientHops.push({
      forwardDigest: new TorDigest(seedF),
      backwardDigest: new TorDigest(seedB),
      forwardCipher: new TorStreamCipher(keyF),
      backwardCipher: new TorStreamCipher(keyB),
    });

    relayHops.push({
      forwardDigest: new TorDigest(seedF),
      backwardDigest: new TorDigest(seedB),
      forwardCipher: new TorStreamCipher(keyF),
      backwardCipher: new TorStreamCipher(keyB),
    });
  }

  // 1. Exit relay (Hop 2) sends a response cell back to Client:
  // Exit packages payload using its backwardDigest (Db)
  const data = new TextEncoder().encode("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello");
  const exitPayload = new Uint8Array(509);
  const view = new DataView(exitPayload.buffer, exitPayload.byteOffset, exitPayload.byteLength);
  view.setUint8(0, RelayCommand.DATA);
  view.setUint16(1, 0, false); // Recognized = 0
  view.setUint16(3, 1, false); // Stream ID 1
  view.setUint32(5, 0, false); // Digest = 0
  view.setUint16(9, data.length, false);
  exitPayload.set(data, 11);

  const digestTag = relayHops[2].backwardDigest.updateAndGetTag(exitPayload);
  exitPayload.set(digestTag, 5);

  // 2. Encrypt in backward direction: Exit -> Middle -> Guard
  let cellOnWire = relayHops[2].backwardCipher.process(exitPayload);
  cellOnWire = relayHops[1].backwardCipher.process(cellOnWire);
  cellOnWire = relayHops[0].backwardCipher.process(cellOnWire);

  // 3. Client receives cell from Guard and peels all 3 layers
  const peeled = peelRelayPayload(cellOnWire, clientHops);
  assertEquals(peeled.hopIndex, 2);
  assertEquals(peeled.relayCell.command, RelayCommand.DATA);
  assertEquals(peeled.relayCell.streamId, 1);
  assertEquals(peeled.relayCell.data, data);
});
