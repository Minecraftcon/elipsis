# 🛡️ Elipsis

> **Pure TypeScript, 0-Dependency Embeddable Tor Client & Hidden Services (v3 .onion) Engine.**  
> Built for **Deno**, **Cloudflare Workers**, **Supabase Edge Functions**, **Node.js**, and Modern Web runtimes.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Deno](https://img.shields.io/badge/Deno-Compatible-green.svg)](https://deno.com)
[![TypeScript](https://img.shields.io/badge/TypeScript-100%25-blue.svg)](https://www.typescriptlang.org)
[![Zero Dependencies](https://img.shields.io/badge/Dependencies-0-brightgreen.svg)]()

---

## ✨ Features

- **🚀 100% Pure TypeScript**: Zero native binaries, zero C bindings, zero npm external dependencies.
- **🧅 Complete v3 Hidden Services (HSv3)**:
  - Base32 address parsing & checksum validation.
  - Blinded key & subcredential derivation.
  - 256-bit circular hash ring HSDir calculation.
  - Rendezvous protocol (`ESTABLISH_RENDEZVOUS`, `INTRODUCE1`, `RENDEZVOUS2`).
- **⚡ Multiple Security & Speed Modes**:
  - **Turbo Direct (1-Hop)**: Clearnet speeds (~200–400ms) for scraping & indexing.
  - **Balanced (2-Hop)**: Speed + IP privacy from Rendezvous Points.
  - **Standard (3-Hop)**: Full standard Tor anonymity circuit.
  - **Paranoid (4+ Hops)**: Custom multi-hop isolation chains.
- **🔌 Embedded Proxy Servers**:
  - Standalone **SOCKS5 Proxy Server** (`127.0.0.1:9055`).
  - Standalone **HTTP / HTTPS CONNECT Forward Proxy** (`127.0.0.1:8080`).
- **🌊 High-Throughput Streaming**: 16KB zero-copy buffers, proactive flow control (`SENDME`), and circuit pooling.

---

## 📦 Installation

### Deno / JSR
```bash
deno add @shado/elipsis
```

### Node.js / npm
```bash
npm install elipsis
```

---

## 🚀 Quick Start

### 1. Simple HTTP Fetch over Tor
```typescript
import { TorClient, SecurityMode } from "./mod.ts";

const client = new TorClient({
  securityMode: SecurityMode.TURBO_DIRECT,
});

// Fetch darknet .onion or clearnet sites
const response = await client.fetch("http://search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion/");
console.log(response.status); // 200
console.log(await response.text());
```

### 2. Start Embedded SOCKS5 & HTTP Proxies
```typescript
import { startSocksProxy, startHttpProxy, SecurityMode } from "./mod.ts";

// Start SOCKS5 proxy on port 9055
const socks = await startSocksProxy({
  port: 9055,
  securityMode: SecurityMode.TURBO_DIRECT,
});
console.log(`SOCKS5 proxy listening on socks5://${socks.host}:${socks.port}`);

// Start HTTP forward proxy on port 8080
const http = await startHttpProxy({
  port: 8080,
  securityMode: SecurityMode.TURBO_DIRECT,
});
console.log(`HTTP proxy listening on http://${http.host}:${http.port}`);
```

### 3. Edge Function & Web Framework Middleware
```typescript
import { createTorEdgeProxyHandler } from "./mod.ts";

// Deno.serve / Supabase Edge Function handler
Deno.serve(createTorEdgeProxyHandler({
  allowedDomains: ["*.onion"],
}));
```

---

## 🛡️ Security Modes Reference

| Mode | Hops | Speed | Security Level | Best Use Case |
| :--- | :---: | :---: | :---: | :--- |
| **`SecurityMode.TURBO_DIRECT`** (`"turbo"`) | **1 Hop** | 🚀 **~200–400ms** | 🔒 End-to-End Encrypted, Direct to RP | Scraping, indexing, high-speed browsing |
| **`SecurityMode.BALANCED`** (`"balanced"`) | **2 Hops** | ⚡ **~500–800ms** | 🛡️ Guard $\rightarrow$ RP (Hides IP from RP) | Balance between speed and privacy |
| **`SecurityMode.STANDARD`** (`"standard"`) | **3 Hops** | 🐢 **~1.5s–3.0s** | 🏰 Standard Tor Anonymity (Guard $\rightarrow$ Mid $\rightarrow$ RP) | Full unlinkable anonymity |
| **`SecurityMode.PARANOID`** (`"paranoid"`) | **4+ Hops** | ⏳ **~3.0s+** | 🛡️ Multi-hop relay isolation chain | High-threat environments |

---

## 🧪 Testing & Verification

Run the automated test suite and trial dashboard:

```bash
# Run all unit tests (19 passed | 0 failed)
deno task test

# Run live API trial dashboard
deno task trial

# Run comprehensive API demonstration
deno task examples
```

---

## 📜 License

MIT License © 2026 Shado
