/**
 * Tor Cell encoder and decoder for fixed 514-byte cells and variable-length cells.
 */
import { BufferReader, BufferWriter } from "../common/buffer_reader.ts";
import { CELL_LEN, CellCommand, isVariableLengthCell } from "./constants.ts";
import { TorProtocolError } from "../common/errors.ts";

/**
 * Raw Tor wire cell structure.
 */
export interface TorCell {
  /** 32-bit circuit identifier (or 16-bit in legacy links) */
  circuitId: number;
  /** Cell command code */
  command: CellCommand;
  /** Fixed or variable payload bytes */
  payload: Uint8Array;
}

/**
 * Encode a Tor cell into wire format bytes.
 * @param cell Cell to encode
 * @param linkVersion Negotiated link protocol version (default: 5)
 * @returns Serialized wire bytes
 */
export function encodeCell(cell: TorCell, linkVersion: number = 5): Uint8Array {
  const isVar = isVariableLengthCell(cell.command, linkVersion);

  if (cell.command === CellCommand.VERSIONS) {
    // VERSIONS cell always uses 2-byte circuit ID for backward link compatibility (Section 3)
    const writer = new BufferWriter();
    writer.writeUint16(0); // Circuit ID 0
    writer.writeUint8(CellCommand.VERSIONS);
    writer.writeUint16(cell.payload.length);
    writer.writeBytes(cell.payload);
    return writer.toUint8Array();
  }

  if (isVar) {
    // Variable length cell with 4-byte circuit ID (linkVersion >= 4)
    const writer = new BufferWriter();
    writer.writeUint32(cell.circuitId);
    writer.writeUint8(cell.command);
    writer.writeUint16(cell.payload.length);
    writer.writeBytes(cell.payload);
    return writer.toUint8Array();
  }

  // Fixed 514-byte cell
  const totalPayloadLen = CELL_LEN - 5; // 509 bytes
  if (cell.payload.length > totalPayloadLen) {
    throw new TorProtocolError(
      `Fixed cell payload exceeds ${totalPayloadLen} bytes (got ${cell.payload.length})`
    );
  }

  const writer = new BufferWriter();
  writer.writeUint32(cell.circuitId);
  writer.writeUint8(cell.command);
  writer.writeBytes(cell.payload);
  if (cell.payload.length < totalPayloadLen) {
    writer.writeZeroes(totalPayloadLen - cell.payload.length);
  }

  return writer.toUint8Array();
}

/**
 * Decode a cell from a raw byte buffer.
 * Returns null if the buffer contains insufficient bytes to form a complete cell.
 * @param buffer Input byte buffer
 * @param linkVersion Negotiated link protocol version
 * @returns Decoded cell and bytes consumed, or null if incomplete
 */
export function decodeCell(
  buffer: Uint8Array,
  linkVersion: number = 5
): { cell: TorCell; bytesConsumed: number } | null {
  if (buffer.length < 3) {
    return null;
  }

  // Special case: Initial VERSIONS cell check (2-byte circuit ID)
  if (buffer[2] === CellCommand.VERSIONS) {
    if (buffer.length < 5) return null;
    const circId = new DataView(buffer.buffer, buffer.byteOffset, 2).getUint16(0, false);
    const cmd = buffer[2];
    const len = new DataView(buffer.buffer, buffer.byteOffset + 3, 2).getUint16(0, false);
    const totalLen = 5 + len;
    if (buffer.length < totalLen) return null;

    const payload = buffer.subarray(5, totalLen);
    return {
      cell: { circuitId: circId, command: cmd, payload },
      bytesConsumed: totalLen,
    };
  }

  // Link version >= 4 standard cell framing
  const circIdLen = linkVersion >= 4 ? 4 : 2;
  const headerLen = circIdLen + 1; // CircId + Command

  if (buffer.length < headerLen) return null;

  const reader = new BufferReader(buffer);
  const circId = circIdLen === 4 ? reader.readUint32() : reader.readUint16();
  const command = reader.readUint8();

  const isVar = isVariableLengthCell(command, linkVersion);

  if (isVar) {
    if (buffer.length < headerLen + 2) return null;
    const len = reader.readUint16();
    const totalLen = headerLen + 2 + len;
    if (buffer.length < totalLen) return null;

    const payload = reader.readBytes(len);
    return {
      cell: { circuitId: circId, command, payload },
      bytesConsumed: totalLen,
    };
  }

  // Fixed length cell
  if (buffer.length < CELL_LEN) return null;
  const payload = reader.readBytes(CELL_LEN - headerLen);
  return {
    cell: { circuitId: circId, command, payload },
    bytesConsumed: CELL_LEN,
  };
}
