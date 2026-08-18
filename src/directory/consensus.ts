/**
 * Tor Consensus-microdesc Parser.
 * Parses router status entries, flags, and microdescriptor mappings.
 */
import { RelayInfo } from "../common/types.ts";
import { decodeBase64, decodeHex } from "../crypto/utils.ts";

export interface ParsedConsensus {
  validAfter: Date;
  freshUntil: Date;
  validUntil: Date;
  sharedRandCurrentValue?: Uint8Array;
  relays: Map<string, Partial<RelayInfo>>; // Keyed by RSA identity hex
}

export function parseConsensus(consensusText: string): ParsedConsensus {
  const lines = consensusText.split("\n");
  const relays = new Map<string, Partial<RelayInfo>>();

  let validAfter = new Date();
  let freshUntil = new Date();
  let validUntil = new Date();
  let sharedRandCurrentValue: Uint8Array | undefined = undefined;

  let currentRelay: Partial<RelayInfo> | null = null;
  let currentRsaHex: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    if (line.startsWith("valid-after ")) {
      validAfter = new Date(line.substring(12) + " UTC");
    } else if (line.startsWith("fresh-until ")) {
      freshUntil = new Date(line.substring(12) + " UTC");
    } else if (line.startsWith("valid-until ")) {
      validUntil = new Date(line.substring(12) + " UTC");
    } else if (line.startsWith("shared-rand-current-value ")) {
      const parts = line.split(" ");
      if (parts.length >= 3) {
        try {
          sharedRandCurrentValue = decodeBase64(parts[2]);
        } catch (_e) {}
      }
    } else if (line.startsWith("r ")) {
      // r <nickname> <identity-base64> [<digest>] <pubdate> <pubtime> <ip> <orport> <dirport>
      const parts = line.split(" ");
      if (parts.length >= 6) {
        const nickname = parts[1];
        const identityBase64 = parts[2];
        const ip = parts[parts.length - 3];
        const orPort = parseInt(parts[parts.length - 2], 10);
        const dirPort = parseInt(parts[parts.length - 1], 10);

        try {
          const identityRsa = decodeBase64(identityBase64);
          const rsaHex = Array.from(identityRsa)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join("");

          currentRelay = {
            nickname,
            identityRsa,
            ip,
            orPort: isNaN(orPort) ? 443 : orPort,
            dirPort: isNaN(dirPort) ? 0 : dirPort,
            flags: new Set<string>(),
          };
          currentRsaHex = rsaHex;
          relays.set(rsaHex, currentRelay);
        } catch (_e) {
          currentRelay = null;
          currentRsaHex = null;
        }
      }
    } else if (line.startsWith("m ") && currentRelay) {
      // m <microdesc-hash-base64>
      const parts = line.split(" ");
      if (parts.length >= 2) {
        try {
          currentRelay.microdescriptorDigest = decodeBase64(parts[1]);
        } catch (_e) {
          // Ignore parse errors
        }
      }
    } else if (line.startsWith("s ") && currentRelay && currentRelay.flags) {
      // s <flags...>
      const flags = line.substring(2).split(" ");
      for (const flag of flags) {
        currentRelay.flags.add(flag);
      }
    }
  }

  return {
    validAfter,
    freshUntil,
    validUntil,
    sharedRandCurrentValue,
    relays,
  };
}
