import { assertEquals } from "jsr:@std/assert";
import { TorHttpClient } from "../src/client/http.ts";
import { TorStream } from "../src/common/types.ts";
import { withTor, getEdgeTorClient } from "../src/edge/middleware.ts";

class MockStream implements TorStream {
  streamId = 1;
  written: Uint8Array[] = [];
  responseChunks: Uint8Array[] = [];
  closed = false;

  constructor(mockHttpResponse: string) {
    this.responseChunks = [new TextEncoder().encode(mockHttpResponse)];
  }

  async read(): Promise<Uint8Array | null> {
    if (this.responseChunks.length > 0) {
      return this.responseChunks.shift()!;
    }
    return null;
  }

  async write(data: Uint8Array): Promise<void> {
    this.written.push(data);
  }

  async close(): Promise<void> {
    this.closed = true;
  }
}

Deno.test("TorHttpClient parses HTTP/1.1 response status, headers, and body", async () => {
  const mockHttp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Tor-Test: true\r\n\r\n{\"status\":\"anonymous\"}";
  const stream = new MockStream(mockHttp);

  const res = await TorHttpClient.request(stream, "http://check.torproject.org/api/ip");
  assertEquals(res.status, 200);
  assertEquals(res.statusText, "OK");
  assertEquals(res.headers.get("Content-Type"), "application/json");
  assertEquals(res.headers.get("X-Tor-Test"), "true");

  const json = await res.json();
  assertEquals(json.status, "anonymous");
});

Deno.test("withTor middleware wrapper injects Tor client into request handler", async () => {
  const handler = withTor(async (_req, { tor }) => {
    return new Response(typeof tor.fetch === "function" ? "ready" : "error");
  });

  const response = await handler(new Request("https://supabase.edge.function/"));
  const text = await response.text();
  assertEquals(text, "ready");
});
