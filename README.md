# Elipsis

> Pure TypeScript Tor client and proxy toolkit for Deno, JSR, Supabase Edge Functions, and Node.js-compatible runtimes.

Elipsis is a zero-dependency TypeScript implementation of core Tor client building blocks: circuits, relay cells, onion routing, hidden-service helpers, and local proxy entrypoints. It is designed for embedding in serverless edges, backend services, and local tooling.

## Features

- Pure TypeScript, with no native bindings or external runtime dependencies
- Tor client orchestration with circuit pooling and stream handling
- SOCKS5 proxy server for local applications
- HTTP and HTTPS CONNECT forward proxy server
- Supabase Edge Function helper for proxying through Tor
- v3 `.onion` address parsing, encoding, and blinding helpers
- HTTP/1.1 request/response handling over Tor streams
- Protocol and crypto primitives for Tor cell and handshake workflows

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
- `TorClient.fetch()` is an HTTP-over-Tor client. If you need true browser-grade TLS handling, terminate TLS separately or adapt the transport layer for your deployment.
- The package is optimized for embedding and experimentation. For production deployments, validate directory sources, proxy exposure, and circuit reuse policy for your threat model.

## Testing

```bash
deno test --allow-net --allow-read test/
```

## Project Layout

- `src/client/` Tor client and proxy entrypoints
- `src/circuit/` circuit management and stream orchestration
- `src/crypto/` cryptographic primitives
- `src/directory/` consensus and microdescriptor parsing
- `src/edge/` Deno and Supabase Edge helpers
- `src/hs/` hidden-service helpers
- `src/protocol/` Tor wire-format encoding and decoding

## License

MIT
