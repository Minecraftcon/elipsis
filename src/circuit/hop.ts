/**
 * Represents a single established cryptographic hop in a Tor circuit.
 */
import { RelayInfo } from "../common/types.ts";
import { TorDigest } from "../crypto/digest.ts";
import { TorStreamCipher } from "../crypto/cipher.ts";
import { DerivedHopKeys } from "../crypto/ntor.ts";
import { CircuitHopCrypto } from "../protocol/relay_cell.ts";

/**
 * Represents a single established cryptographic hop in a Tor circuit.
 */
export class Hop implements CircuitHopCrypto {
  /** Relay metadata for this hop */
  public readonly relay: RelayInfo;
  /** Forward running digest */
  public readonly forwardDigest: TorDigest;
  /** Backward running digest */
  public readonly backwardDigest: TorDigest;
  /** Forward AES stream cipher */
  public readonly forwardCipher: TorStreamCipher;
  /** Backward AES stream cipher */
  public readonly backwardCipher: TorStreamCipher;

  /**
   * Constructs a new Hop instance with derived symmetric keys and digest seeds.
   * @param relay Relay information
   * @param keys Derived hop keys from ntor handshake
   */
  constructor(relay: RelayInfo, keys: DerivedHopKeys) {
    this.relay = relay;
    this.forwardDigest = new TorDigest(keys.forwardDigest);
    this.backwardDigest = new TorDigest(keys.backwardDigest);
    this.forwardCipher = new TorStreamCipher(keys.forwardKey);
    this.backwardCipher = new TorStreamCipher(keys.backwardKey);
  }
}
