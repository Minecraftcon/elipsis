/**
 * Tor v3 HSDir hash ring calculator.
 * Matches Tor C codebase (hs_common.c hs_get_responsible_hsdirs).
 */
import { RelayInfo } from "../common/types.ts";
import { buildHsdirIndex, buildHsIndex } from "./blinding.ts";

/** Compare two byte arrays */
function compareUint8Arrays(a: Uint8Array, b: Uint8Array): number {
  const len = Math.min(a.length, b.length);
  for (let i = 0; i < len; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return a.length - b.length;
}

export interface HsdirCandidate {
  relay: RelayInfo;
  ringIndex: Uint8Array;
}

export class HsdirRing {
  /**
   * Select responsible HSDir relays for a hidden service.
   * @param relays List of candidate relays from consensus
   * @param blindedPublicKey 32-byte blinded public key
   * @param srvValue 32-byte shared random value from consensus
   * @param timePeriod Current time period
   * @param count Total responsible HSDirs to select per replica
   */
  static selectResponsibleHsdirs(
    relays: RelayInfo[],
    blindedPublicKey: Uint8Array,
    srvValue: Uint8Array,
    timePeriod: number,
    count: number = 3
  ): RelayInfo[] {
    const hsdirRelays = relays.filter(
      (r) => r.flags.has("HSDir") && r.identityEd25519 && r.identityEd25519.length === 32
    );

    if (hsdirRelays.length === 0) {
      return relays.slice(0, count);
    }

    const ring: HsdirCandidate[] = hsdirRelays.map((relay) => ({
      relay,
      ringIndex: buildHsdirIndex(relay.identityEd25519!, srvValue, timePeriod),
    }));

    // Sort in ascending ring order
    ring.sort((a, b) => compareUint8Arrays(a.ringIndex, b.ringIndex));

    const selectedMap = new Map<string, RelayInfo>();

    // Tor standard: replicas 1 and 2
    for (const replica of [1, 2]) {
      const hsIndex = buildHsIndex(replica, blindedPublicKey, timePeriod);
      let startIdx = ring.findIndex((node) => compareUint8Arrays(node.ringIndex, hsIndex) >= 0);
      if (startIdx === -1) startIdx = 0;

      let addedForReplica = 0;
      for (let i = 0; i < ring.length && addedForReplica < count; i++) {
        const node = ring[(startIdx + i) % ring.length];
        const key = `${node.relay.ip}:${node.relay.orPort}`;
        if (!selectedMap.has(key)) {
          selectedMap.set(key, node.relay);
          addedForReplica++;
        }
      }
    }

    return Array.from(selectedMap.values());
  }
}
