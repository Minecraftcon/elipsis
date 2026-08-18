/**
 * Tor wire protocol constants and command definitions.
 * Conforms to tor-spec.txt.
 */

export const CELL_LEN = 514; // Fixed cell length for link protocol >= 4
export const RELAY_HEADER_LEN = 11; // Relay cell header length
export const RELAY_PAYLOAD_LEN = 509; // Fixed relay cell payload length
export const MAX_RELAY_DATA_LEN = 498; // 509 - 11 = 498 max data bytes in a single relay cell

/**
 * Fixed and variable cell command codes (tor-spec Section 3).
 */
export enum CellCommand {
  PADDING = 0,
  CREATE = 1,
  CREATED = 2,
  RELAY = 3,
  DESTROY = 4,
  CREATE_FAST = 5,
  CREATED_FAST = 6,
  VERSIONS = 7, // Variable length
  NETINFO = 8,
  RELAY_EARLY = 9,
  CREATE2 = 10,
  CREATED2 = 11,
  PADDING_NEGOTIATE = 12,
  VPADDING = 128, // Variable length
  CERTS = 129, // Variable length
  AUTH_CHALLENGE = 130, // Variable length
  AUTHENTICATE = 131, // Variable length
  AUTHORIZE = 132, // Variable length
}

/**
 * Tor Relay cell command types (tor-spec Section 6.1).
 */
export enum RelayCommand {
  BEGIN = 1,
  DATA = 2,
  END = 3,
  CONNECTED = 4,
  SENDME = 5,
  EXTEND = 6,
  EXTENDED = 7,
  TRUNCATE = 8,
  TRUNCATED = 9,
  DROP = 10,
  RESOLVE = 11,
  RESOLVED = 12,
  BEGIN_DIR = 13,
  EXTEND2 = 14,
  EXTENDED2 = 15,
  ESTABLISH_INTRO = 32,
  ESTABLISH_RENDEZVOUS = 33,
  INTRODUCE1 = 34,
  INTRODUCE2 = 35,
  RENDEZVOUS1 = 36,
  RENDEZVOUS2 = 37,
  INTRO_ESTABLISHED = 38,
  RENDEZVOUS_ESTABLISHED = 39,
  INTRODUCE_ACK = 40,
  PADDING_NEGOTIATE = 41,
  PADDING_NEGOTIATED = 42,
}

/**
 * Tor circuit destruction reason codes (tor-spec Section 5.4).
 */
export enum DestroyReason {
  NONE = 0,
  PROTOCOL = 1,
  INTERNAL = 2,
  REQUESTED = 3,
  HIBERNATING = 4,
  RESOURCELIMIT = 5,
  CONNECTFAILED = 6,
  OR_IDENTITY = 7,
  CHANNEL_CLOSED = 8,
  FINISHED = 9,
  TIMEOUT = 10,
  DESTROYED = 11,
  NOSUCHSERVICE = 12,
}

export enum HandshakeType {
  TAP = 0x0000,
  RESERVED = 0x0001,
  NTOR = 0x0002,
  NTOR_V3 = 0x0003,
}

export enum LinkSpecifierType {
  TLS_OVER_IPV4 = 0x00,
  TLS_OVER_IPV6 = 0x01,
  LEGACY_IDENTITY = 0x02, // 20 bytes SHA-1 RSA
  ED25519_IDENTITY = 0x03, // 32 bytes Ed25519
}

export function isVariableLengthCell(command: number, linkVersion: number): boolean {
  if (command === CellCommand.VERSIONS) return true;
  if (linkVersion >= 3 && (command === CellCommand.VPADDING || command >= 128)) {
    return true;
  }
  return false;
}
