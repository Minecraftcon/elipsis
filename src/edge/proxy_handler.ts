/**
 * Supabase Edge Function Web / API Gateway Proxy Handler.
 * Enables exposing a Supabase Edge Function as an HTTP proxy endpoint for clearnet and .onion URLs.
 */
import { TorClient } from "../client/tor_client.ts";
import { getEdgeTorClient } from "./middleware.ts";

/**
 * Options for configuring the HTTP edge proxy handler.
 */
export interface EdgeProxyOptions {
  /** Optional custom TorClient instance */
  torClient?: TorClient;
  /** Allowed origins for CORS */
  allowedOrigins?: string[];
  /** Whether to inject permissive CORS headers (default: true) */
  enableCors?: boolean;
}

/**
 * Creates a standard fetch request handler for Supabase Edge Functions / Deno.serve.
 *
 * @example
 * ```ts
 * import { createTorEdgeProxyHandler } from "@shado/elipsis";
 *
 * Deno.serve(createTorEdgeProxyHandler());
 * ```
 *
 * Client query:
 * `GET https://project.supabase.co/functions/v1/tor-proxy?url=http://example.onion`
 *
 * @param options Edge proxy configuration options
 * @returns Request handler function for Deno.serve
 */
export function createTorEdgeProxyHandler(options: EdgeProxyOptions = {}): (req: Request) => Promise<Response> {
  const tor = options.torClient || getEdgeTorClient();
  const enableCors = options.enableCors !== false;

  return async (req: Request): Promise<Response> => {
    const corsHeaders: Record<string, string> = enableCors
      ? {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS, HEAD",
          "Access-Control-Allow-Headers": "*",
        }
      : {};

    if (req.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      const reqUrl = new URL(req.url);
      const targetUrl = reqUrl.searchParams.get("url") || req.headers.get("x-target-url");

      if (!targetUrl) {
        return new Response(
          JSON.stringify({
            error: "Missing target URL",
            usage: "Provide ?url=http://...onion or 'x-target-url' header",
          }),
          {
            status: 400,
            headers: { "Content-Type": "application/json", ...corsHeaders },
          }
        );
      }

      // Forward request body if present
      let body: any = undefined;
      if (req.method !== "GET" && req.method !== "HEAD") {
        const arrayBuf = await req.arrayBuffer();
        if (arrayBuf.byteLength > 0) {
          body = new Uint8Array(arrayBuf);
        }
      }

      const safeHeaders = new Headers(req.headers);
      const hopByHop = [
        "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
        "te", "trailers", "transfer-encoding", "upgrade", "host", "x-forwarded-for"
      ];
      hopByHop.forEach(h => safeHeaders.delete(h));

      const response = await tor.fetch(targetUrl, {
        method: req.method,
        headers: safeHeaders,
        body,
      });

      const responseHeaders = new Headers(response.headers);
      for (const [k, v] of Object.entries(corsHeaders)) {
        responseHeaders.set(k, v);
      }

      return new Response(response.body as any, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (err: any) {
      return new Response(
        JSON.stringify({
          error: "Tor proxy error",
          message: err?.message || String(err),
        }),
        {
          status: 502,
          headers: { "Content-Type": "application/json", ...corsHeaders },
        }
      );
    }
  };
}
