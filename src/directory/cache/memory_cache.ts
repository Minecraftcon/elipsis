/**
 * In-memory directory cache with TTL support.
 */
import { DirectoryCache, RelayInfo } from "../../common/types.ts";

export class MemoryDirectoryCache implements DirectoryCache {
  private consensus: string | null = null;
  private consensusExpiry = 0;
  private descriptors: Map<string, RelayInfo> | null = null;
  private descriptorsExpiry = 0;

  async getConsensus(): Promise<string | null> {
    if (this.consensus && Date.now() < this.consensusExpiry) {
      return this.consensus;
    }
    return null;
  }

  async setConsensus(consensus: string, ttlSeconds: number): Promise<void> {
    this.consensus = consensus;
    this.consensusExpiry = Date.now() + ttlSeconds * 1000;
  }

  async getMicrodescriptors(): Promise<Map<string, RelayInfo> | null> {
    if (this.descriptors && Date.now() < this.descriptorsExpiry) {
      return this.descriptors;
    }
    return null;
  }

  async setMicrodescriptors(descriptors: Map<string, RelayInfo>, ttlSeconds: number): Promise<void> {
    this.descriptors = descriptors;
    this.descriptorsExpiry = Date.now() + ttlSeconds * 1000;
  }
}
