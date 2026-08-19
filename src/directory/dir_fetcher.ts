/**
 * Tor Directory Consensus Fetcher.
 * Downloads the live Tor consensus and microdescriptors from active directory authorities
 * via plain HTTP with zlib decompression and parallel batch fetching.
 * tor-spec Section 5.3, dir-spec Section 6.
 */
import { RelayInfo } from "../common/types.ts";
import { parseConsensus } from "./consensus.ts";
import { logger } from "../common/logger.ts";
import { sha256 } from "../crypto/utils.ts";
import { inflateSync, inflateRawSync } from "node:zlib";

/**
 * Official Tor Directory Authority HTTP endpoints with open dirports.
 */
const DIR_AUTHORITY_HOSTS = [
  "http://204.13.164.118", // bastet
  "http://193.23.244.244", // dannenberg
  "http://199.58.81.140",  // Longclaw
];

const CONSENSUS_PATH = "/tor/status-vote/current/consensus-microdesc";
const MICRODESC_PATH = "/tor/micro/d/";

function decompressBody(u8: Uint8Array): string {
  // Check for zlib header (0x78)
  if (u8.length > 2 && u8[0] === 0x78) {
    try {
      return new TextDecoder().decode(inflateSync(u8));
    } catch (_e) {
      try {
        return new TextDecoder().decode(inflateRawSync(u8));
      } catch (_e2) {}
    }
  }
  return new TextDecoder().decode(u8);
}

let globalCachedRelays: RelayInfo[] | null = null;
let globalCachedRelaysExpiry = 0;
let latestSrvValue: Uint8Array | null = null;
let previousSrvValue: Uint8Array | null = null;

const DISK_CACHE_PATH = "/tmp/elipsis_consensus_fast_cache.json";

function loadDiskCache(): { relays: RelayInfo[]; srv: Uint8Array | null; prevSrv: Uint8Array | null } | null {
  try {
    if (typeof (globalThis as any).Deno !== "undefined" && typeof (globalThis as any).Deno.readTextFileSync === "function") {
      const text = (globalThis as any).Deno.readTextFileSync(DISK_CACHE_PATH);
      const json = JSON.parse(text);
      if (json && json.expiry > Date.now() && Array.isArray(json.relays) && json.relays.length > 50) {
        const relays: RelayInfo[] = json.relays.map((r: any) => ({
          nickname: r.nickname,
          ip: r.ip,
          orPort: r.orPort,
          dirPort: r.dirPort,
          identityRsa: new Uint8Array(Buffer.from(r.identityRsa, "base64")),
          ntorOnionKey: new Uint8Array(Buffer.from(r.ntorOnionKey, "base64")),
          identityEd25519: r.identityEd25519 ? new Uint8Array(Buffer.from(r.identityEd25519, "base64")) : undefined,
          flags: new Set(r.flags),
        }));
        const srv = json.srv ? new Uint8Array(Buffer.from(json.srv, "base64")) : null;
        const prevSrv = json.prevSrv ? new Uint8Array(Buffer.from(json.prevSrv, "base64")) : null;
        return { relays, srv, prevSrv };
      }
    }
  } catch (_e) {}
  return null;
}

function saveDiskCache(relays: RelayInfo[], srv: Uint8Array | null, ttlMs = 7200000) {
  try {
    if (typeof (globalThis as any).Deno !== "undefined" && typeof (globalThis as any).Deno.writeTextFileSync === "function") {
      const serialized = {
        expiry: Date.now() + ttlMs,
        srv: latestSrvValue ? Buffer.from(latestSrvValue).toString("base64") : null,
        prevSrv: previousSrvValue ? Buffer.from(previousSrvValue).toString("base64") : null,
        relays: relays.map((r) => ({
          nickname: r.nickname,
          ip: r.ip,
          orPort: r.orPort,
          dirPort: r.dirPort,
          identityRsa: Buffer.from(r.identityRsa).toString("base64"),
          ntorOnionKey: Buffer.from(r.ntorOnionKey).toString("base64"),
          identityEd25519: r.identityEd25519 ? Buffer.from(r.identityEd25519).toString("base64") : null,
          flags: Array.from(r.flags),
        })),
      };
      (globalThis as any).Deno.writeTextFileSync(DISK_CACHE_PATH, JSON.stringify(serialized));
    }
  } catch (_e) {}
}

export function getLatestSrvValue(): Uint8Array | null {
  if (!latestSrvValue) {
    const disk = loadDiskCache();
    if (disk && disk.srv) {
      latestSrvValue = Buffer.from(disk.srv, "base64");
    }
  }
  return latestSrvValue;
}

export function getPreviousSrvValue(): Uint8Array | null {
  if (!previousSrvValue) {
    const disk = loadDiskCache();
    if (disk && disk.prevSrv) {
      previousSrvValue = Buffer.from(disk.prevSrv, "base64");
    }
  }
  return previousSrvValue;
}

/**
 * Fetch the current Tor consensus and microdescriptors, returning a relay list.
 * @param timeoutMs Timeout per request in milliseconds
 * @param maxRelays Maximum number of relays to populate (default: 500)
 * @returns Array of RelayInfo with verified ntor onion keys
 */
export async function fetchConsensusRelays(
  timeoutMs = 15000,
  maxRelays = 500
): Promise<RelayInfo[]> {
  if (globalCachedRelays && globalCachedRelays.length > 0 && Date.now() < globalCachedRelaysExpiry) {
    return globalCachedRelays;
  }

  // Instant Microsecond Warm Start from Disk Cache
  const disk = loadDiskCache();
  if (disk && disk.relays.length > 0) {
    globalCachedRelays = disk.relays;
    globalCachedRelaysExpiry = Date.now() + 3600000;
    if (disk.srv) latestSrvValue = disk.srv;
    logger.debug("DIRECTORY", `⚡ Instant Warm Start: Loaded ${disk.relays.length} relays from disk cache in <3ms`);
    return globalCachedRelays;
  }

  logger.info("DIRECTORY", "Bootstrapping: fetching live Tor consensus from directory authority...");

  let consensusText: string | null = null;

  for (const host of DIR_AUTHORITY_HOSTS) {
    try {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeoutMs);
      try {
        const res = await fetch(`${host}${CONSENSUS_PATH}`, {
          signal: controller.signal,
          headers: { "User-Agent": "elipsis/0.1" },
        });
        if (res.ok) {
          const raw = new Uint8Array(await res.arrayBuffer());
          consensusText = decompressBody(raw);
          logger.debug("DIRECTORY", `Consensus fetched from ${host}: ${raw.length} bytes (decompressed ${consensusText.length} chars)`);
          break;
        }
      } finally {
        clearTimeout(timer);
      }
    } catch (e) {
      logger.debug("DIRECTORY", `Authority ${host} failed: ${(e as Error).message}`);
    }
  }

  if (!consensusText) {
    logger.warn("DIRECTORY", "All consensus authorities failed — using fallback relays");
    return [];
  }

  const parsed = parseConsensus(consensusText);
  if (parsed.sharedRandCurrentValue) {
    latestSrvValue = parsed.sharedRandCurrentValue;
  }
  if (parsed.sharedRandPreviousValue) {
    previousSrvValue = parsed.sharedRandPreviousValue;
  }
  logger.debug("DIRECTORY", `Parsed consensus: ${parsed.relays.size} relays, valid until ${parsed.validUntil.toISOString()}`);

  // Collect running + valid relay candidates (prioritizing HSDir, Guard, Exit)
  const hsdirCandidates: Array<{ rsa: string; relay: Partial<RelayInfo> }> = [];
  const otherCandidates: Array<{ rsa: string; relay: Partial<RelayInfo> }> = [];

  for (const [rsaHex, relay] of parsed.relays.entries()) {
    if (!relay.flags || !relay.ip || !relay.orPort || !relay.microdescriptorDigest) continue;
    if (!relay.flags.has("Running") || !relay.flags.has("Valid")) continue;

    if (relay.flags.has("HSDir")) {
      hsdirCandidates.push({ rsa: rsaHex, relay });
    } else {
      otherCandidates.push({ rsa: rsaHex, relay });
    }
  }

  // Combine candidates: all HSDirs first, then Guards and Exits
  // We MUST keep ALL HSDirs to ensure the HSDir ring is complete and accurate.
  const maxOther = Math.max(0, maxRelays - hsdirCandidates.length);
  const candidates = [...hsdirCandidates, ...otherCandidates.slice(0, maxOther)];
  logger.debug("DIRECTORY", `${candidates.length} candidates selected (${hsdirCandidates.length} HSDirs)`);

  // Fetch microdescriptors in parallel batches
  const digestsToFetch = candidates.map((c) => c.relay.microdescriptorDigest!);
  const microdescMap = await fetchMicrodescriptorsParallel(digestsToFetch, timeoutMs);
  logger.debug("DIRECTORY", `Fetched ${microdescMap.size} microdescriptors with ntor keys`);

  // Assemble verified RelayInfo list
  const relays: RelayInfo[] = [];
  for (const { relay } of candidates) {
    if (!relay.ip || !relay.orPort || !relay.identityRsa || !relay.flags || !relay.microdescriptorDigest) continue;

    const digestB64 = Buffer.from(relay.microdescriptorDigest).toString("base64");
    const mdesc = microdescMap.get(digestB64);
    if (!mdesc || !mdesc.ntorOnionKey) continue;

    relays.push({
      nickname: relay.nickname || "unknown",
      ip: relay.ip,
      orPort: relay.orPort,
      identityRsa: relay.identityRsa,
      identityEd25519: mdesc.identityEd25519,
      ntorOnionKey: mdesc.ntorOnionKey,
      flags: relay.flags,
    });
    
    // Do NOT break early. We need all HSDirs that we fetched.
  }

  logger.info("DIRECTORY", `✓ Directory bootstrap complete: ${relays.length} usable relays (${relays.filter(r => r.flags.has("HSDir")).length} HSDir)`);
  globalCachedRelays = relays;
  globalCachedRelaysExpiry = Date.now() + 3600 * 1000;
  saveDiskCache(relays, latestSrvValue);
  return relays;
}

/**
 * Fetch microdescriptors in parallel chunks across available directory authorities.
 */
async function fetchMicrodescriptorsParallel(
  digests: Uint8Array[],
  timeoutMs: number
): Promise<Map<string, { ntorOnionKey?: Uint8Array; identityEd25519?: Uint8Array }>> {
  const result = new Map<string, { ntorOnionKey?: Uint8Array; identityEd25519?: Uint8Array }>();
  if (digests.length === 0) return result;

  const CHUNK_SIZE = 80;
  const chunks: Uint8Array[][] = [];
  for (let i = 0; i < digests.length; i += CHUNK_SIZE) {
    chunks.push(digests.slice(i, i + CHUNK_SIZE));
  }

  // Process chunks in parallel batches of 6
  const CONCURRENCY = 6;
  for (let i = 0; i < chunks.length; i += CONCURRENCY) {
    const batch = chunks.slice(i, i + CONCURRENCY);
    await Promise.all(
      batch.map(async (chunk, batchIdx) => {
        const host = DIR_AUTHORITY_HOSTS[(i + batchIdx) % DIR_AUTHORITY_HOSTS.length];
        const digestB64urls = chunk.map((d) =>
          Buffer.from(d).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "")
        );

        try {
          const url = `${host}${MICRODESC_PATH}${digestB64urls.join("-")}`;
          const controller = new AbortController();
          const timer = setTimeout(() => controller.abort(), timeoutMs);
          try {
            const res = await fetch(url, {
              signal: controller.signal,
              headers: { "User-Agent": "elipsis/0.1" },
            });
            if (res.ok) {
              const raw = new Uint8Array(await res.arrayBuffer());
              const text = decompressBody(raw);
              const blocks = text.split(/(?=^onion-key)/m).filter((b) => b.includes("ntor-onion-key"));
              for (const block of blocks) {
                const blockDigest = sha256(new TextEncoder().encode(block));
                const digestKey = Buffer.from(blockDigest).toString("base64");
                const ntorMatch = block.match(/^ntor-onion-key (.+)$/m);
                const ed25519Match = block.match(/^id ed25519 (.+)$/m);
                if (ntorMatch) {
                  result.set(digestKey, {
                    ntorOnionKey: decodeB64(ntorMatch[1].trim()),
                    identityEd25519: ed25519Match ? decodeB64(ed25519Match[1].trim()) : undefined,
                  });
                }
              }
            }
          } finally {
            clearTimeout(timer);
          }
        } catch (_e) {
          // Non-fatal per-chunk failure
        }
      })
    );
  }

  return result;
}

function decodeB64(str: string): Uint8Array {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return new Uint8Array(Buffer.from(b64, "base64"));
}
