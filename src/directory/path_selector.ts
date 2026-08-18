/**
 * Tor Path Selection Algorithm (dir-spec & path-spec).
 * Selects 3 distinct hops: Guard -> Middle -> Exit.
 */
import { RelayInfo } from "../common/types.ts";
import { DirectoryError } from "../common/errors.ts";

export interface PathSelectionCriteria {
  targetPort?: number;
  excludeRelays?: Set<string>; // Set of RSA hex fingerprints
}

export class PathSelector {
  /**
   * Extract /16 subnet prefix from IPv4 string (e.g. "192.168.1.1" -> "192.168").
   */
  private static getSubnet16(ip: string): string {
    const parts = ip.split(".");
    if (parts.length >= 2) {
      return `${parts[0]}.${parts[1]}`;
    }
    return ip;
  }

  /**
   * Select a full 3-hop path for a circuit.
   */
  static select3HopPath(
    relays: RelayInfo[],
    criteria: PathSelectionCriteria = {}
  ): [RelayInfo, RelayInfo, RelayInfo] {
    if (relays.length < 3) {
      throw new DirectoryError(`Not enough relays in directory to select a path (found ${relays.length})`);
    }

    const targetPort = criteria.targetPort || 443;
    const excluded = criteria.excludeRelays || new Set<string>();

    // 1. Filter candidates
    const guards = relays.filter(
      (r) =>
        r.flags.has("Guard") &&
        r.flags.has("Fast") &&
        r.flags.has("Running") &&
        r.flags.has("Valid") &&
        !excluded.has(r.nickname)
    );

    const exits = relays.filter(
      (r) =>
        r.flags.has("Exit") &&
        !r.flags.has("BadExit") &&
        r.flags.has("Running") &&
        r.flags.has("Valid") &&
        !excluded.has(r.nickname)
    );

    const middles = relays.filter(
      (r) =>
        r.flags.has("Fast") &&
        r.flags.has("Running") &&
        r.flags.has("Valid") &&
        !excluded.has(r.nickname)
    );

    const guardCandidates = guards.length > 0 ? guards : relays.filter((r) => r.flags.has("Running"));
    const exitCandidates = exits.length > 0 ? exits : relays.filter((r) => r.flags.has("Running"));
    const middleCandidates = middles.length > 0 ? middles : relays.filter((r) => r.flags.has("Running"));

    // 2. Select Guard
    const guard = guardCandidates[Math.floor(Math.random() * guardCandidates.length)];
    const guardSubnet = PathSelector.getSubnet16(guard.ip);

    // 3. Select Exit (distinct from Guard and distinct /16)
    const validExits = exitCandidates.filter(
      (r) => r.nickname !== guard.nickname && PathSelector.getSubnet16(r.ip) !== guardSubnet
    );
    const exit = validExits.length > 0
      ? validExits[Math.floor(Math.random() * validExits.length)]
      : exitCandidates.find((r) => r.nickname !== guard.nickname) || exitCandidates[0];

    const exitSubnet = PathSelector.getSubnet16(exit.ip);

    // 4. Select Middle (distinct from Guard & Exit, distinct /16s)
    const validMiddles = middleCandidates.filter(
      (r) =>
        r.nickname !== guard.nickname &&
        r.nickname !== exit.nickname &&
        PathSelector.getSubnet16(r.ip) !== guardSubnet &&
        PathSelector.getSubnet16(r.ip) !== exitSubnet
    );

    const middle = validMiddles.length > 0
      ? validMiddles[Math.floor(Math.random() * validMiddles.length)]
      : middleCandidates.find((r) => r.nickname !== guard.nickname && r.nickname !== exit.nickname) ||
        middleCandidates[0];

    return [guard, middle, exit];
  }
}
