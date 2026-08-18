/**
 * Supabase Edge Functions presets and configurations.
 */
import { TorClientOptions } from "../common/types.ts";

/**
 * Recommended lightweight options optimized for memory-constrained Edge environments (Cloudflare Workers, Supabase).
 */
export const EDGE_FUNCTION_PRESETS: TorClientOptions = {
  circuitBuildTimeoutMs: 12000,
  streamTimeoutMs: 15000,
  maxPoolCircuits: 1, // Minimize memory footprint under Edge 150MB budget
};
