/**
 * Tor Pinned Entry Guard Manager.
 * Implements Tor path-spec Section 5 & guard-spec.
 * 
 * Guards protect against traffic confirmation attacks and reduce handshake jitter
 * by restricting entry points to a persistent, high-bandwidth set of relays (default: 3).
 * Pinned guards are persisted to disk (/tmp/elipsis_pinned_guards.json) for instant warm restarts.
 */
import { RelayInfo } from "../common/types.ts";
import { sampleRelayWeighted, PathSelector } from "./path_selector.ts";
import { logger } from "../common/logger.ts";

export interface PinnedGuardRecord {
  rsaHex: string;
  nickname: string;
  ip: string;
  orPort: number;
  addedAt: number;
  failures: number;
}

const PINNED_GUARDS_DISK_PATH = "/tmp/elipsis_pinned_guards.json";

function getRsaHex(relay: RelayInfo | Uint8Array | string): string {
  if (typeof relay === "string") return relay.toLowerCase();
  const bytes = "identityRsa" in relay ? relay.identityRsa : relay;
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toLowerCase();
}

export class GuardManager {
  private static inMemoryGuards: PinnedGuardRecord[] | null = null;

  /**
   * Load pinned guards from disk cache.
   */
  private static loadDisk(): PinnedGuardRecord[] {
    if (this.inMemoryGuards !== null) {
      return this.inMemoryGuards;
    }
    try {
      if (
        typeof (globalThis as any).Deno !== "undefined" &&
        typeof (globalThis as any).Deno.readTextFileSync === "function"
      ) {
        const text = (globalThis as any).Deno.readTextFileSync(PINNED_GUARDS_DISK_PATH);
        const data = JSON.parse(text);
        if (Array.isArray(data)) {
          this.inMemoryGuards = data;
          return data;
        }
      }
    } catch (_e) {}
    this.inMemoryGuards = [];
    return [];
  }

  /**
   * Persist pinned guards to disk cache.
   */
  private static saveDisk(records: PinnedGuardRecord[]): void {
    this.inMemoryGuards = records;
    try {
      if (
        typeof (globalThis as any).Deno !== "undefined" &&
        typeof (globalThis as any).Deno.writeTextFileSync === "function"
      ) {
        (globalThis as any).Deno.writeTextFileSync(
          PINNED_GUARDS_DISK_PATH,
          JSON.stringify(records, null, 2)
        );
      }
    } catch (_e) {}
  }

  /**
   * Retrieve active pinned Entry Guards, populating with fresh BWRS-selected guards if needed.
   * @param relays Full list of relays from consensus
   * @param numGuards Number of primary entry guards to maintain (default: 3)
   * @returns Array of active RelayInfo objects for the pinned guards
   */
  static getGuards(relays: RelayInfo[], numGuards = 3): RelayInfo[] {
    if (relays.length === 0) return [];

    const existingRecords = this.loadDisk();
    const relayMap = new Map<string, RelayInfo>();
    for (const r of relays) {
      relayMap.set(getRsaHex(r), r);
    }

    // Filter existing pinned records that are still valid and active in consensus
    const validGuards: RelayInfo[] = [];
    const retainedRecords: PinnedGuardRecord[] = [];

    for (const rec of existingRecords) {
      const liveRelay = relayMap.get(rec.rsaHex);
      if (
        liveRelay &&
        liveRelay.flags.has("Guard") &&
        !liveRelay.flags.has("Exit") &&
        liveRelay.flags.has("Running") &&
        rec.failures < 3
      ) {
        validGuards.push(liveRelay);
        retainedRecords.push(rec);
      }
    }

    // If we have enough valid pinned guards, return them
    if (validGuards.length >= numGuards) {
      return validGuards.slice(0, numGuards);
    }

    // Otherwise, sample additional high-bandwidth guards via BWRS
    const pinnedRsaSet = new Set(retainedRecords.map((r) => r.rsaHex));
    const pinnedSubnets = new Set(validGuards.map((g) => PathSelector.getSubnet16(g.ip)));

    let candidates = relays.filter(
      (r) =>
        r.flags.has("Guard") &&
        !r.flags.has("Exit") &&
        !r.flags.has("BadExit") &&
        r.flags.has("Fast") &&
        r.flags.has("Running") &&
        r.flags.has("Valid") &&
        !pinnedRsaSet.has(getRsaHex(r)) &&
        !pinnedSubnets.has(PathSelector.getSubnet16(r.ip))
    );

    while (validGuards.length < numGuards && candidates.length > 0) {
      const chosen = sampleRelayWeighted(candidates);
      const chosenRsa = getRsaHex(chosen);
      const chosenSubnet = PathSelector.getSubnet16(chosen.ip);

      validGuards.push(chosen);
      retainedRecords.push({
        rsaHex: chosenRsa,
        nickname: chosen.nickname,
        ip: chosen.ip,
        orPort: chosen.orPort,
        addedAt: Date.now(),
        failures: 0,
      });

      pinnedRsaSet.add(chosenRsa);
      pinnedSubnets.add(chosenSubnet);

      candidates = candidates.filter(
        (c) =>
          !pinnedRsaSet.has(getRsaHex(c)) &&
          !pinnedSubnets.has(PathSelector.getSubnet16(c.ip))
      );
    }

    this.saveDisk(retainedRecords);
    logger.debug(
      "GUARD",
      `Active Pinned Entry Guards (${validGuards.length}/${numGuards}): ${validGuards.map((g) => g.nickname).join(", ")}`
    );

    return validGuards.length > 0 ? validGuards : relays.slice(0, 1);
  }

  /**
   * Select a single pinned entry guard using Bandwidth-Weighted Relay Sampling.
   * Falls back gracefully if all pinned guards are excluded.
   * @param relays Full list of relays
   * @param excludeIps Optional set of IPs to exclude (e.g. rendezvous point or intro point IP)
   * @param numGuards Number of pinned guards
   */
  static selectGuard(
    relays: RelayInfo[],
    excludeIps?: Set<string>,
    numGuards = 3
  ): RelayInfo {
    const guards = this.getGuards(relays, numGuards);
    const eligible = excludeIps
      ? guards.filter((g) => !excludeIps.has(g.ip))
      : guards;

    if (eligible.length > 0) {
      return sampleRelayWeighted(eligible);
    }

    // Fallback if pinned guards conflict with excluded IPs
    const fallbackCandidates = relays.filter(
      (r) =>
        r.flags.has("Guard") &&
        !r.flags.has("Exit") &&
        r.flags.has("Running") &&
        (!excludeIps || !excludeIps.has(r.ip))
    );

    if (fallbackCandidates.length > 0) {
      return sampleRelayWeighted(fallbackCandidates);
    }

    return relays[0];
  }

  /**
   * Record a successful connection to a guard to maintain its healthy status.
   */
  static markSuccess(relayOrRsa: RelayInfo | string): void {
    const rsaHex = getRsaHex(relayOrRsa);
    const records = this.loadDisk();
    const match = records.find((r) => r.rsaHex === rsaHex);
    if (match && match.failures > 0) {
      match.failures = 0;
      this.saveDisk(records);
    }
  }

  /**
   * Record a connection failure for a guard.
   * Once a guard reaches 3 consecutive failures, it is evicted and rotated.
   */
  static markFailure(relayOrRsa: RelayInfo | string): void {
    const rsaHex = getRsaHex(relayOrRsa);
    const records = this.loadDisk();
    const match = records.find((r) => r.rsaHex === rsaHex);
    if (match) {
      match.failures += 1;
      if (match.failures >= 3) {
        logger.warn("GUARD", `Evicting unhealthy guard ${match.nickname} (${match.ip}) after 3 failures`);
        this.saveDisk(records.filter((r) => r.rsaHex !== rsaHex));
        return;
      }
      this.saveDisk(records);
    }
  }

  /**
   * Clear the pinned guards cache (forcing full re-selection).
   */
  static reset(): void {
    this.inMemoryGuards = [];
    try {
      if (
        typeof (globalThis as any).Deno !== "undefined" &&
        typeof (globalThis as any).Deno.removeSync === "function"
      ) {
        (globalThis as any).Deno.removeSync(PINNED_GUARDS_DISK_PATH);
      }
    } catch (_e) {}
  }
}

