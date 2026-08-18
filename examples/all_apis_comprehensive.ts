/**
 * ============================================================================
 * ELIPSIS - Comprehensive Pure TypeScript API Reference & Examples
 * ============================================================================
 * This file demonstrates all core APIs, security presets, and proxy servers
 * available in the Elipsis engine without any external dependencies.
 *
 * Run with:
 *   deno run --allow-all elipsis/examples/all_apis_comprehensive.ts
 * ============================================================================
 */

import {
  TorClient,
  startSocksProxy,
  startHttpProxy,
  SecurityMode,
  ConnectionMode,
  parseOnionV3Address,
  encodeOnionV3Address,
  deriveSubcredential,
  getCurrentTimePeriod,
  computeDescriptorIndex,
  createNtorClientHandshake,
  CircuitBuilder,
  DEFAULT_FALLBACK_RELAYS,
  createTorEdgeProxyHandler,
  withTor,
} from "../mod.ts";

async function main() {
  console.log("================================================================");
  console.log("🌟 ELIPSIS PURE TYPESCRIPT TOR API COMPREHENSIVE SUITE");
  console.log("================================================================");

  // --------------------------------------------------------------------------
  // API 1: TorClient Instantiation & Security Profiles
  // --------------------------------------------------------------------------
  console.log("\n[1] Initializing TorClient with Custom Security & Relay Options...");

  const client = new TorClient({
    securityMode: SecurityMode.TURBO_DIRECT, // "turbo" | "balanced" | "standard" | "paranoid"
    relayCount: 1,                           // 1 to 5 hops
    connectionMode: ConnectionMode.POOL,     // Pre-warmed circuit pool
    maxPoolCircuits: 3,                      // Keep 3 warm circuits in memory
    streamTimeoutMs: 20000,
    debug: false,
  });

  console.log("✓ TorClient initialized successfully.");

  // Dynamic Profile Re-configuration at runtime
  client.setProfile(SecurityMode.BALANCED, 2);
  console.log("✓ Runtime profile updated to BALANCED (2-Hop mode).");

  // --------------------------------------------------------------------------
  // API 2: v3 Onion Address Cryptography & Validation
  // --------------------------------------------------------------------------
  console.log("\n[2] v3 Hidden Service Cryptography Primitives...");

  const onionDomain = "search7tdrcvri22rieiwgi5g46qnwsesvnubqav2xakhezv4hjzkkad.onion";
  const parsed = parseOnionV3Address(onionDomain);

  console.log(`• Parsed Onion:    ${parsed.hostname}`);
  console.log(`• Protocol Version: v${parsed.version}`);
  console.log(`• Ed25519 PubKey:  ${parsed.publicKey.length} bytes`);
  console.log(`• Checksum Valid:  ${parsed.checksum.length} bytes`);

  // Subcredential & HSDir Blinding Index Derivation
  const timePeriod = getCurrentTimePeriod();
  const subcredential = deriveSubcredential(parsed.publicKey, timePeriod);
  const descriptorIndex = computeDescriptorIndex(subcredential);
  console.log(`• Current Time Period:   ${timePeriod}`);
  console.log(`• Derived Subcredential: ${subcredential.length} bytes (SHA256)`);
  console.log(`• HSDir Ring Index:      ${descriptorIndex.length} bytes`);

  // --------------------------------------------------------------------------
  // API 3: Pure-TS Ntor Handshake Generation
  // --------------------------------------------------------------------------
  console.log("\n[3] Curve25519 Ntor Handshake Generator...");

  const sampleGuard = DEFAULT_FALLBACK_RELAYS[0];
  const { clientHandshake, state } = createNtorClientHandshake(
    sampleGuard.identityRsa,
    sampleGuard.ntorOnionKey
  );
  console.log(`• Target Guard Relay: ${sampleGuard.nickname} (${sampleGuard.ip}:${sampleGuard.orPort})`);
  console.log(`• Client Handshake:   ${clientHandshake.length} bytes (NTOR_ONION_KEY + IDENTITY_RSA + Ephemeral X)`);
  console.log(`• Ephemeral Private:  ${state.ephemeralPrivateKey.length} bytes (Scalar Secret)`);

  // --------------------------------------------------------------------------
  // API 4: Embedded SOCKS5 Proxy Server
  // --------------------------------------------------------------------------
  console.log("\n[4] Starting Embedded SOCKS5 Proxy Server...");

  const socks = await startSocksProxy({
    port: 9060,
    securityMode: SecurityMode.TURBO_DIRECT,
    relayCount: 1,
  });
  console.log(`✓ SOCKS5 Server listening on socks5://${socks.host}:${socks.port}`);

  // --------------------------------------------------------------------------
  // API 5: Embedded HTTP / HTTPS CONNECT Forward Proxy Server
  // --------------------------------------------------------------------------
  console.log("\n[5] Starting Embedded HTTP Forward & CONNECT Proxy Server...");

  const httpProxy = await startHttpProxy({
    port: 8090,
    securityMode: SecurityMode.TURBO_DIRECT,
  });
  console.log(`✓ HTTP Proxy Server listening on http://${httpProxy.host}:${httpProxy.port}`);

  // --------------------------------------------------------------------------
  // API 6: Edge Function & Web Framework Middleware
  // --------------------------------------------------------------------------
  console.log("\n[6] Edge Function Proxy Handler Middleware...");

  const edgeHandler = createTorEdgeProxyHandler({
    client,
    allowedDomains: ["*.onion"],
  });
  console.log("✓ Edge proxy handler generated for Deno / Cloudflare / Supabase Edge Functions.");

  // Clean shutdown of demo proxies
  socks.client.close().catch(() => {});
  httpProxy.client.close().catch(() => {});

  console.log("\n================================================================");
  console.log("🎉 ALL API DEMONSTRATIONS EXECUTED CLEANLY");
  console.log("================================================================");
  if (typeof (globalThis as any).Deno !== "undefined") {
    (globalThis as any).Deno.exit(0);
  } else if (typeof process !== "undefined") {
    process.exit(0);
  }
}

if ((import.meta as any).main || (typeof process !== "undefined" && process.argv[1]?.includes("all_apis_comprehensive"))) {
  main();
}
