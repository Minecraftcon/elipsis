/**
 * Circuit construction engine (CREATE2 + RELAY_EXTEND2).
 * Implements Tor Protocol Specification Section 5.1.
 */
import { TorLinkConnection } from "../transport/link.ts";
import { TorCircuit } from "./circuit.ts";
import { Hop } from "./hop.ts";
import { RelayInfo } from "../common/types.ts";
import {
  completeNtorClientHandshake,
  createNtorClientHandshake,
} from "../crypto/ntor.ts";
import { BufferReader, BufferWriter } from "../common/buffer_reader.ts";
import { CellCommand, HandshakeType, RelayCommand } from "../protocol/constants.ts";
import {
  createEd25519LinkSpecifier,
  createIPv4LinkSpecifier,
  createLegacyIdLinkSpecifier,
  encodeLinkSpecifiers,
  type LinkSpecifier,
} from "../protocol/link_specifier.ts";
import { CircuitError } from "../common/errors.ts";
import { randomBytes } from "../crypto/utils.ts";

/**
 * Tor multi-hop circuit construction engine (CREATE2 + RELAY_EXTEND2).
 */
export class CircuitBuilder {
  /**
   * Allocate a fresh Circuit ID where MSB is 1 (for client initiator in Link Protocol >= 4).
   * @returns 32-bit positive integer circuit ID
   */
  static generateCircuitId(): number {
    const rand = new DataView(randomBytes(4).buffer).getUint32(0, false);
    return ((0x80000000 | (rand & 0x7fffffff)) >>> 0);
  }

  /**
   * Build a 1-hop direct circuit to a relay (ultra-fast single-hop mode).
   * @param guard Target relay
   * @param timeoutMs Timeout in milliseconds
   * @returns Established 1-hop circuit
   */
  static async build1HopCircuit(
    guard: RelayInfo,
    timeoutMs = 10000
  ): Promise<TorCircuit> {
    const link = await TorLinkConnection.connect(guard.ip, guard.orPort);
    const circId = CircuitBuilder.generateCircuitId();
    const circuit = new TorCircuit(circId, link);

    try {
      await CircuitBuilder.createFirstHop(circuit, guard, timeoutMs);
      return circuit;
    } catch (err) {
      await circuit.destroy();
      link.close();
      throw err;
    }
  }

  /**
   * Build a fast circuit of arbitrary hop length (1-hop, 2-hop, or 3-hop).
   * @param relays Ordered list of relays to construct the circuit path through
   * @param timeoutMs Timeout in milliseconds
   * @returns Established multi-hop circuit
   */
  static async buildFastCircuit(
    relays: RelayInfo[],
    timeoutMs = 15000
  ): Promise<TorCircuit> {
    if (relays.length === 1) {
      return CircuitBuilder.build1HopCircuit(relays[0], timeoutMs);
    }
    const guard = relays[0];
    const link = await TorLinkConnection.connect(guard.ip, guard.orPort);
    const circId = CircuitBuilder.generateCircuitId();
    const circuit = new TorCircuit(circId, link);

    try {
      await CircuitBuilder.createFirstHop(circuit, guard, timeoutMs);
      for (let i = 1; i < relays.length; i++) {
        await CircuitBuilder.extendHop(circuit, relays[i], timeoutMs);
      }
      return circuit;
    } catch (err) {
      await circuit.destroy();
      link.close();
      throw err;
    }
  }

  /**
   * Build a 3-hop circuit through Guard, Middle, and Exit relays.
   */
  static async build3HopCircuit(
    path: [RelayInfo, RelayInfo, RelayInfo],
    timeoutMs = 15000
  ): Promise<TorCircuit> {
    return CircuitBuilder.buildFastCircuit(path, timeoutMs);
  }

  /**
   * Establish first hop using CREATE2 cell.
   */
  private static async createFirstHop(
    circuit: TorCircuit,
    guard: RelayInfo,
    timeoutMs: number
  ): Promise<void> {
    const { clientHandshake, state } = createNtorClientHandshake(
      guard.identityRsa,
      guard.ntorOnionKey
    );

    const writer = new BufferWriter();
    writer.writeUint16(HandshakeType.NTOR);
    writer.writeUint16(clientHandshake.length);
    writer.writeBytes(clientHandshake);

    const createdPromise = new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        circuit.controlListener = null;
        reject(new CircuitError(`Timeout establishing first hop to ${guard.nickname}`, circuit.circuitId));
      }, timeoutMs);

      circuit.controlListener = (cell) => {
        if (cell.command === CellCommand.CREATED2) {
          clearTimeout(timer);
          circuit.controlListener = null;
          const reader = new BufferReader(cell.payload);
          const hlen = reader.readUint16();
          const hdata = reader.readBytes(hlen);
          resolve(hdata);
        } else if (cell.command === CellCommand.DESTROY) {
          clearTimeout(timer);
          circuit.controlListener = null;
          reject(new CircuitError(`Received DESTROY cell while creating first hop`, circuit.circuitId));
        }
      };
    });

    // Send CREATE2 cell
    await circuit.link.sendCell({
      circuitId: circuit.circuitId,
      command: CellCommand.CREATE2,
      payload: writer.toUint8Array(),
    });

    const serverHandshake = await createdPromise;
    const hopKeys = completeNtorClientHandshake(serverHandshake, state);
    circuit.addHop(new Hop(guard, hopKeys));
  }

  /**
   * Extend circuit to the next relay using RELAY_EXTEND2 cell.
   */
  private static async extendHop(
    circuit: TorCircuit,
    targetRelay: RelayInfo,
    timeoutMs: number
  ): Promise<void> {
    const { clientHandshake, state } = createNtorClientHandshake(
      targetRelay.identityRsa,
      targetRelay.ntorOnionKey
    );

    // Link specifiers: IPv4 + Legacy RSA ID + Ed25519 ID (if available)
    const specifiers: LinkSpecifier[] = [
      createIPv4LinkSpecifier(targetRelay.ip, targetRelay.orPort),
      createLegacyIdLinkSpecifier(targetRelay.identityRsa),
    ];

    if (targetRelay.identityEd25519) {
      specifiers.push(createEd25519LinkSpecifier(targetRelay.identityEd25519));
    }

    const encodedSpecifiers = encodeLinkSpecifiers(specifiers);

    const writer = new BufferWriter();
    writer.writeBytes(encodedSpecifiers);
    writer.writeUint16(HandshakeType.NTOR);
    writer.writeUint16(clientHandshake.length);
    writer.writeBytes(clientHandshake);

    const extendedPromise = new Promise<Uint8Array>((resolve, reject) => {
      const timer = setTimeout(() => {
        circuit.unregisterStream(0);
        reject(new CircuitError(`Timeout extending circuit to ${targetRelay.nickname}`, circuit.circuitId));
      }, timeoutMs);

      circuit.registerStream(0, (relayCell) => {
        if (relayCell.command === RelayCommand.EXTENDED2) {
          clearTimeout(timer);
          circuit.unregisterStream(0);
          const reader = new BufferReader(relayCell.data);
          const hlen = reader.readUint16();
          const hdata = reader.readBytes(hlen);
          resolve(hdata);
        } else if (relayCell.command === RelayCommand.TRUNCATED) {
          clearTimeout(timer);
          circuit.unregisterStream(0);
          reject(new CircuitError(`Circuit was truncated while extending to ${targetRelay.nickname}`, circuit.circuitId));
        }
      });
    });

    // Send RELAY_EXTEND2 as RELAY_EARLY cell
    await circuit.sendRelayCell(
      RelayCommand.EXTEND2,
      0,
      writer.toUint8Array(),
      circuit.hopCount - 1,
      true // force RELAY_EARLY
    );

    const serverHandshake = await extendedPromise;
    const hopKeys = completeNtorClientHandshake(serverHandshake, state);
    circuit.addHop(new Hop(targetRelay, hopKeys));
  }
}
