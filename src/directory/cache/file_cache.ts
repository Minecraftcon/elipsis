/**
 * Filesystem-backed Directory Cache for ultra-fast Tor client cold starts.
 */
import { DirectoryCache, RelayInfo } from "../../common/types.ts";

export class FileDirectoryCache implements DirectoryCache {
  private cachePath: string;

  constructor(cachePath = "/tmp/elipsis_consensus_cache.json") {
    this.cachePath = cachePath;
  }

  async getConsensus(): Promise<string | null> {
    try {
      const data = Deno.readTextFileSync(this.cachePath);
      const parsed = JSON.parse(data);
      if (parsed.expiry && Date.now() < parsed.expiry && parsed.consensus) {
        return parsed.consensus;
      }
    } catch (_e) {
      // ignore
    }
    return null;
  }

  async setConsensus(consensus: string, ttlSeconds = 3600): Promise<void> {
    try {
      const payload = {
        consensus,
        expiry: Date.now() + ttlSeconds * 1000,
      };
      Deno.writeTextFileSync(this.cachePath, JSON.stringify(payload));
    } catch (_e) {
      // ignore
    }
  }

  async getMicrodescriptors(): Promise<Map<string, RelayInfo> | null> {
    return null;
  }

  async setMicrodescriptors(_descriptors: Map<string, RelayInfo>, _ttlSeconds: number): Promise<void> {
    // optional
  }
}
