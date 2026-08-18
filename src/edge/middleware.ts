/**
 * @module
 * Supabase Edge Functions middleware and helper utilities.
 * Allows wrapping Edge Functions with an auto-managed TorClient singleton.
 */
import { TorClient } from "../client/tor_client.ts";
import { TorClientOptions } from "../common/types.ts";
import { EDGE_FUNCTION_PRESETS } from "./config.ts";

let edgeTorClientInstance: TorClient | null = null;

/**
 * Get or initialize the singleton Tor client for warm Supabase Edge Function invocations.
 * @param customOptions Optional configuration overrides
 * @returns TorClient instance
 */
export function getEdgeTorClient(customOptions: TorClientOptions = {}): TorClient {
  if (!edgeTorClientInstance) {
    edgeTorClientInstance = new TorClient({
      ...EDGE_FUNCTION_PRESETS,
      ...customOptions,
    });
  }
  return edgeTorClientInstance;
}

/**
 * Higher-order helper for Supabase Edge Functions.
 * Injects a ready-to-use tor client instance into the standard Deno.serve handler.
 *
 * @example
 * ```ts
 * import { withTor } from "@shado/elipsis/edge";
 *
 * Deno.serve(withTor(async (req, { tor }) => {
 *   const response = await tor.fetch("http://example.onion");
 *   return new Response(await response.text());
 * }));
 * ```
 * @param handler Edge Function handler receiving standard Request and Tor context
 * @param options TorClient configuration options
 * @returns Wrapped Deno.serve compatible request handler
 */
export function withTor(
  handler: (req: Request, ctx: { tor: TorClient }) => Promise<Response> | Response,
  options: TorClientOptions = {}
): (req: Request) => Promise<Response> {
  const tor = getEdgeTorClient(options);
  return async (req: Request) => {
    return await handler(req, { tor });
  };
}
