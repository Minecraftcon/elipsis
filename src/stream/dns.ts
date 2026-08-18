/**
 * Anonymous Remote DNS Resolution over Tor circuits (RELAY_RESOLVE / RELAY_RESOLVED).
 * Implements Tor Protocol Specification Section 6.4.
 */
import { TorCircuit } from "../circuit/circuit.ts";
import { RelayCommand } from "../protocol/constants.ts";
import { BufferReader } from "../common/buffer_reader.ts";
import { StreamError } from "../common/errors.ts";

/**
 * Resolved DNS record returned by anonymous Tor DNS lookup.
 */
export interface DnsAnswer {
  /** Record type */
  type: "ipv4" | "ipv6" | "hostname" | "error";
  /** Resolved IP address or hostname */
  address?: string;
  /** Time-to-live in seconds */
  ttlSeconds?: number;
}

/**
 * Remote DNS resolver client engine over Tor circuits.
 */
export class TorDnsResolver {
  /**
   * Resolve a hostname anonymously over a Tor circuit.
   * @param circuit Active Tor circuit
   * @param hostname Target domain name
   * @param streamId Stream ID allocated for query
   * @param timeoutMs Query timeout in milliseconds
   * @returns List of resolved DNS records
   */
  static async resolve(
    circuit: TorCircuit,
    hostname: string,
    streamId = 100,
    timeoutMs = 10000
  ): Promise<DnsAnswer[]> {
    const queryPayload = new TextEncoder().encode(`${hostname}\0`);

    const resolvePromise = new Promise<DnsAnswer[]>((resolve, reject) => {
      const timer = setTimeout(() => {
        circuit.unregisterStream(streamId);
        reject(new StreamError(`DNS resolution timeout for ${hostname}`, streamId));
      }, timeoutMs);

      circuit.registerStream(streamId, (relayCell) => {
        if (relayCell.command === RelayCommand.RESOLVED) {
          clearTimeout(timer);
          circuit.unregisterStream(streamId);

          const answers: DnsAnswer[] = [];
          const reader = new BufferReader(relayCell.data);

          while (reader.remaining >= 2) {
            const type = reader.readUint8();
            const len = reader.readUint8();
            if (reader.remaining < len) break;

            const val = reader.readBytes(len);
            const ttl = reader.remaining >= 4 ? reader.readUint32() : 300;

            if (type === 0x04 && len === 4) {
              const ip = `${val[0]}.${val[1]}.${val[2]}.${val[3]}`;
              answers.push({ type: "ipv4", address: ip, ttlSeconds: ttl });
            } else if (type === 0x06 && len === 16) {
              answers.push({ type: "ipv6", ttlSeconds: ttl });
            } else if (type === 0xf0 || type === 0xf1) {
              answers.push({ type: "error" });
            }
          }

          resolve(answers);
        } else if (relayCell.command === RelayCommand.END) {
          clearTimeout(timer);
          circuit.unregisterStream(streamId);
          reject(new StreamError(`DNS resolution failed with RELAY_END`, streamId));
        }
      });
    });

    await circuit.sendRelayCell(RelayCommand.RESOLVE, streamId, queryPayload);
    return await resolvePromise;
  }
}
