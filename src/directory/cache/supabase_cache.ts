/**
 * Supabase Storage / Database Directory Cache Adapter.
 * Allows Supabase Edge Functions to share and persist Tor consensus and microdescriptors
 * across cold starts without downloading megabytes from relays on each invocation.
 */
import { DirectoryCache, RelayInfo } from "../../common/types.ts";

export interface SupabaseClientLike {
  storage: {
    from(bucket: string): {
      download(path: string): Promise<{ data: Blob | null; error: any }>;
      upload(path: string, data: string | Uint8Array, options?: any): Promise<{ data: any; error: any }>;
    };
  };
}

export class SupabaseStorageDirectoryCache implements DirectoryCache {
  private client: SupabaseClientLike;
  private bucket: string;
  private memoryFallback = new Map<string, any>();

  constructor(supabaseClient: SupabaseClientLike, bucket = "tor-cache") {
    this.client = supabaseClient;
    this.bucket = bucket;
  }

  async getConsensus(): Promise<string | null> {
    try {
      const { data, error } = await this.client.storage.from(this.bucket).download("consensus.txt");
      if (error || !data) return null;
      return await data.text();
    } catch (_e) {
      return this.memoryFallback.get("consensus") || null;
    }
  }

  async setConsensus(consensus: string, _ttlSeconds: number): Promise<void> {
    this.memoryFallback.set("consensus", consensus);
    try {
      await this.client.storage.from(this.bucket).upload("consensus.txt", consensus, {
        upsert: true,
        contentType: "text/plain",
      });
    } catch (_e) {}
  }

  async getMicrodescriptors(): Promise<Map<string, RelayInfo> | null> {
    return this.memoryFallback.get("microdescriptors") || null;
  }

  async setMicrodescriptors(descriptors: Map<string, RelayInfo>, _ttlSeconds: number): Promise<void> {
    this.memoryFallback.set("microdescriptors", descriptors);
  }
}
