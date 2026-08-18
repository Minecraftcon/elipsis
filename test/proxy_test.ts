import { assertEquals } from "jsr:@std/assert";
import { createTorEdgeProxyHandler } from "../src/edge/proxy_handler.ts";
import { TorClient } from "../src/client/tor_client.ts";

Deno.test("createTorEdgeProxyHandler returns 400 when url param is missing", async () => {
  const handler = createTorEdgeProxyHandler();
  const req = new Request("https://supabase.functions/proxy");
  const res = await handler(req);

  assertEquals(res.status, 400);
  const json = await res.json();
  assertEquals(json.error, "Missing target URL");
});

Deno.test("createTorEdgeProxyHandler handles CORS preflight OPTIONS request", async () => {
  const handler = createTorEdgeProxyHandler({ enableCors: true });
  const req = new Request("https://supabase.functions/proxy", { method: "OPTIONS" });
  const res = await handler(req);

  assertEquals(res.status, 204);
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "*");
});

Deno.test("TorClient has proxy initialization methods", () => {
  const client = new TorClient();
  assertEquals(typeof client.createSocksServer, "function");
  assertEquals(typeof client.createHttpProxyServer, "function");
});
