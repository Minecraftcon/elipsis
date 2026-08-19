# Elipsis

> Pure TypeScript Tor client and proxy toolkit for Deno, JSR, Supabase Edge Functions, and Node.js-compatible runtimes.

Elipsis is a TypeScript implementation of core Tor client components. These include circuits, relay cells, onion routing, hidden-service helpers, and local proxy entry points. It's made for use in serverless edges, backend services, and local tools.

## Features

- Pure TypeScript, without native bindings or external runtime dependencies
- Tor client management with circuit pooling and stream handling
- SOCKS5 proxy server for local applications
- HTTP and HTTPS CONNECT forward proxy server
- Supabase Edge Function helper for proxying through Tor
- v3 `.onion` address parsing, encoding, and blinding helpers
- HTTP/1.1 request/response handling over Tor streams
- Protocol and cryptographic elements for Tor cell and handshake workflows

## Experimental: WebAssembly MTCW Mode

Elipsis now supports an optional **Multi-Threaded Crypto Worker (MTCW)** engine powered by WebAssembly. When enabled, heavy cryptographic operations (like AES-CTR stream ciphering and Curve25519 Ntor handshakes) are offloaded to background threads. This bypasses V8 engine GC pauses and enables C-Tor level gigabit streaming speeds in Node and Deno.

To use Wasm acceleration, simply pass `enableWasm: true`:

```ts
import { TorClient } from "jsr:@shado/elipsis";

// Dynamically boots the Wasm Engine. If unsupported (e.g. Edge environments), 
// it seamlessly and gracefully falls back to the pure TypeScript engine!
const tor = new TorClient({ enableWasm: true });
```

## Install

### Deno / JSR

```bash
deno add jsr:@shado/elipsis
```

```ts
import { TorClient } from "jsr:@shado/elipsis";
```

### From source

```bash
git clone https://github.com/Minecraftcon/elipsis.git
cd elipsis
deno test --allow-net --allow-read test/
```

## Quick Start

### Tor client

```ts
import { TorClient } from "jsr:@shado/elipsis";

const tor = new TorClient();

const response = await tor.fetch("http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/");
console.log(response.status);
console.log(await response.text());
```

### SOCKS5 proxy

```ts
import { startSocksProxy } from "jsr:@shado/elipsis";

const { host, port } = await startSocksProxy({ port: 9050 });
console.log(`SOCKS5 listening on socks5://${host}:${port}`);
```

### HTTP CONNECT proxy

```ts
import { startHttpProxy } from "jsr:@shado/elipsis";

const { host, port } = await startHttpProxy({ port: 8080 });
console.log(`HTTP proxy listening on http://${host}:${port}`);
```

### Edge function handler

```ts
import { createTorEdgeProxyHandler } from "jsr:@shado/elipsis";

Deno.serve(createTorEdgeProxyHandler());
```

## Usage Notes

- Bind local proxies to `127.0.0.1` unless you add authentication and access controls in front of them.
- `TorClient.fetch()` is an HTTP-over-Tor client. If you need true browser-grade TLS handling, handle TLS separately or adjust the transport layer for your setup.
- The package is made for embedding and experimentation. For production use, check directory sources, proxy exposure, and circuit reuse policy based on your security needs.

## Testing 

```bash
deno test --allow-net --allow-read test/
```

## Project Layout

- `src/client/` Tor client and proxy entry points
- `src/circuit/` circuit management and stream control
- `src/crypto/` cryptographic elements
- `src/directory/` consensus and microdescriptor parsing
- `src/edge/` Deno and Supabase Edge helpers
- `src/hs/` hidden-service helpers
- `src/protocol/` Tor wire-format encoding and decoding

## License

MIT