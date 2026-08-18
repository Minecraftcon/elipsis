/**
 * Tor protocol and client error definitions.
 */

/**
 * Base class for all Elipsis Tor client errors.
 */
export class TorError extends Error {
  /**
   * Constructs a new TorError.
   * @param message Human-readable error message
   * @param code Optional machine-readable error code
   */
  constructor(message: string, public readonly code?: string) {
    super(message);
    this.name = "TorError";
  }
}

/**
 * Thrown when an unexpected wire-protocol or cell violation occurs.
 */
export class TorProtocolError extends TorError {
  /**
   * Constructs a new TorProtocolError.
   * @param message Description of the protocol violation
   * @param code Optional error code
   */
  constructor(message: string, code?: string) {
    super(message, code);
    this.name = "TorProtocolError";
  }
}

/**
 * Thrown when circuit construction, extension, or teardown fails.
 */
export class CircuitError extends TorError {
  /**
   * Constructs a new CircuitError.
   * @param message Error description
   * @param circuitId Associated circuit ID
   * @param code Optional error code
   */
  constructor(message: string, public readonly circuitId?: number, code?: string) {
    super(message, code);
    this.name = "CircuitError";
  }
}

/**
 * Thrown when stream data transmission or lifecycle fails.
 */
export class StreamError extends TorError {
  /**
   * Constructs a new StreamError.
   * @param message Error description
   * @param streamId Associated stream ID
   * @param code Optional error code
   */
  constructor(message: string, public readonly streamId?: number, code?: string) {
    super(message, code);
    this.name = "StreamError";
  }
}

/**
 * Thrown when directory consensus or descriptor fetch fails.
 */
export class DirectoryError extends TorError {
  /**
   * Constructs a new DirectoryError.
   * @param message Error description
   * @param code Optional error code
   */
  constructor(message: string, code?: string) {
    super(message, code);
    this.name = "DirectoryError";
  }
}

/**
 * Thrown when cryptographic handshakes, digests, or decryption fails.
 */
export class CryptoError extends TorError {
  /**
   * Constructs a new CryptoError.
   * @param message Error description
   * @param code Optional error code
   */
  constructor(message: string, code?: string) {
    super(message, code);
    this.name = "CryptoError";
  }
}

/**
 * Thrown when v3 onion service descriptor fetch or rendezvous fails.
 */
export class HiddenServiceError extends TorError {
  /**
   * Constructs a new HiddenServiceError.
   * @param message Error description
   * @param code Optional error code
   */
  constructor(message: string, code?: string) {
    super(message, code);
    this.name = "HiddenServiceError";
  }
}
