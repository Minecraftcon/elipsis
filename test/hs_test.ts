import { assertEquals, assertThrows } from "jsr:@std/assert";
import {
  parseOnionV3Address,
  encodeOnionV3Address,
  computeOnionV3Checksum,
} from "../src/hs/address.ts";
import {
  getCurrentTimePeriod,
  deriveSubcredential,
  computeDescriptorIndex,
} from "../src/hs/blinding.ts";
import { HsdirRing } from "../src/hs/hsdir.ts";
import { RelayInfo } from "../src/common/types.ts";
import { randomBytes } from "../src/crypto/utils.ts";

Deno.test("v3 onion address encoding and decoding roundtrip", () => {
  const dummyPubkey = randomBytes(32);
  const onionAddress = encodeOnionV3Address(dummyPubkey);

  assertEquals(onionAddress.endsWith(".onion"), true);
  assertEquals(onionAddress.length, 56 + 6); // 56 chars + .onion

  const parsed = parseOnionV3Address(onionAddress);
  assertEquals(parsed.publicKey, dummyPubkey);
  assertEquals(parsed.version, 3);
  assertEquals(parsed.checksum.length, 2);
});

Deno.test("duckduckgo v3 onion address parsing and validation", () => {
  // DuckDuckGo official v3 onion address
  const ddgOnion = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
  const parsed = parseOnionV3Address(ddgOnion);

  assertEquals(parsed.version, 3);
  assertEquals(parsed.publicKey.length, 32);
  assertEquals(parsed.checksum.length, 2);
  assertEquals(parsed.hostname, ddgOnion);
});

Deno.test("v3 onion address error detection on corrupted character", () => {
  const ddgCorrupted = "euckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion";
  assertThrows(() => {
    parseOnionV3Address(ddgCorrupted);
  });
});

Deno.test("time period and subcredential derivation", () => {
  const pubkey = new Uint8Array(32).fill(0x42);
  const timePeriod = getCurrentTimePeriod(1700000000000);
  const subcred = deriveSubcredential(pubkey, timePeriod);
  assertEquals(subcred.length, 32);

  const descIdx = computeDescriptorIndex(subcred);
  assertEquals(descIdx.length, 32);
});

Deno.test("HsdirRing selects responsible relays for descriptor index", () => {
  const relays: RelayInfo[] = [
    {
      nickname: "hsdir1",
      ip: "1.1.1.1",
      orPort: 443,
      dirPort: 80,
      identityRsa: new Uint8Array(20).fill(1),
      ntorOnionKey: new Uint8Array(32).fill(1),
      flags: new Set(["HSDir", "Running", "Valid"]),
    },
    {
      nickname: "hsdir2",
      ip: "2.2.2.2",
      orPort: 443,
      dirPort: 80,
      identityRsa: new Uint8Array(20).fill(2),
      ntorOnionKey: new Uint8Array(32).fill(2),
      flags: new Set(["HSDir", "Running", "Valid"]),
    },
  ];

  const descIdx = new Uint8Array(32).fill(0x10);
  const selected = HsdirRing.selectResponsibleHsdirs(relays, descIdx, 1000, 2);
  assertEquals(selected.length, 2);
});

Deno.test("SecurityMode and relay count configuration options", async () => {
  const { SecurityMode, ConnectionMode, TorClient } = await import("../src/mod.ts");
  
  assertEquals(SecurityMode.TURBO_DIRECT, "turbo");
  assertEquals(SecurityMode.BALANCED, "balanced");
  assertEquals(SecurityMode.STANDARD, "standard");
  assertEquals(SecurityMode.PARANOID, "paranoid");

  const client = new TorClient({
    securityMode: SecurityMode.BALANCED,
    relayCount: 2,
    connectionMode: ConnectionMode.POOL,
  });

  client.setProfile(SecurityMode.TURBO_DIRECT, 1);
});

