/**
 * Tor Path Selection Algorithm (dir-spec & path-spec).
 * Selects 3 distinct hops: Guard -> Middle -> Exit using Bandwidth-Weighted Relay Sampling (BWRS).
 */
import { RelayInfo } from "../common/types.ts";
import { DirectoryError } from "../common/errors.ts";

export interface PathSelectionCriteria {
  targetPort?: number;
  excludeRelays?: Set<string>; // Set of relay nicknames or RSA hex fingerprints
  guard?: RelayInfo; // Explicit or pinned entry guard to use
}

/**
 * Sample a relay from a candidate list using Bandwidth-Weighted Relay Sampling (BWRS).
 * In Tor path-spec Section 2.2, relay selection probability is proportional to consensus bandwidth.
 * Relays with higher bandwidth capacity are selected with proportionally higher probability,
 * preventing slow/flaky nodes from choking circuit throughput and latency.
 */
export function sampleRelayWeighted(candidates: RelayInfo[]): RelayInfo {
  if (candidates.length === 0) {
    throw new DirectoryError("Cannot sample relay from an empty candidate list");
  }
  if (candidates.length === 1) {
    return candidates[0];
  }

  let totalWeight = 0;
  const cumulative = new Float64Array(candidates.length);
  for (let i = 0; i < candidates.length; i++) {
    const bw = candidates[i].bandwidth;
    const w = typeof bw === "number" && bw > 0 ? bw : 20;
    totalWeight += w;
    cumulative[i] = totalWeight;
  }

  if (totalWeight <= 0) {
    return candidates[Math.floor(Math.random() * candidates.length)];
  }

  const r = Math.random() * totalWeight;

  // Binary search for the first index where cumulative[idx] >= r
  let low = 0;
  let high = candidates.length - 1;
  while (low < high) {
    const mid = (low + high) >> 1;
    if (cumulative[mid] < r) {
      low = mid + 1;
    } else {
      high = mid;
    }
  }

  return candidates[low];
}

export class PathSelector {
  /**
   * Extract /16 subnet prefix from IPv4 string (e.g. "192.168.1.1" -> "192.168").
   */
  static getSubnet16(ip: string): string {
    const parts = ip.split(".");
    if (parts.length >= 2) {
      return `${parts[0]}.${parts[1]}`;
    }
    return ip;
  }

  /**
   * Select a full 3-hop path for a circuit using BWRS.
   */
  static select3HopPath(
    relays: RelayInfo[],
    criteria: PathSelectionCriteria = {}
  ): [RelayInfo, RelayInfo, RelayInfo] {
    if (relays.length < 3) {
      throw new DirectoryError(`Not enough relays in directory to select a path (found ${relays.length})`);
    }

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

    // 2. Select Guard (use pre-selected/pinned guard if provided, otherwise BWRS)
    const guard = criteria.guard || sampleRelayWeighted(guardCandidates);
    const guardSubnet = PathSelector.getSubnet16(guard.ip);

    // 3. Select Exit (distinct from Guard and distinct /16) using BWRS
    const validExits = exitCandidates.filter(
      (r) => r.nickname !== guard.nickname && PathSelector.getSubnet16(r.ip) !== guardSubnet
    );
    const exit = validExits.length > 0
      ? sampleRelayWeighted(validExits)
      : exitCandidates.find((r) => r.nickname !== guard.nickname) || exitCandidates[0];

    const exitSubnet = PathSelector.getSubnet16(exit.ip);

    // 4. Select Middle (distinct from Guard & Exit, distinct /16s) using BWRS
    const validMiddles = middleCandidates.filter(
      (r) =>
        r.nickname !== guard.nickname &&
        r.nickname !== exit.nickname &&
        PathSelector.getSubnet16(r.ip) !== guardSubnet &&
        PathSelector.getSubnet16(r.ip) !== exitSubnet
    );

    const middle = validMiddles.length > 0
      ? sampleRelayWeighted(validMiddles)
      : middleCandidates.find((r) => r.nickname !== guard.nickname && r.nickname !== exit.nickname) ||
        middleCandidates[0];

    return [guard, middle, exit];
  }
}
