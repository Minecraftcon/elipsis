import { assertEquals, assertThrows } from "jsr:@std/assert";
import {
  createNtorClientHandshake,
  completeNtorClientHandshake,
} from "../src/crypto/ntor.ts";
import { randomBytes, sha1, sha256 } from "../src/crypto/utils.ts";
import { TorStreamCipher } from "../src/crypto/cipher.ts";
import { TorDigest } from "../src/crypto/digest.ts";

Deno.test("ntor handshake client generation and validation", () => {
  const relayId = randomBytes(20);
  const relayNtorKey = randomBytes(32);

  const { clientHandshake, state } = createNtorClientHandshake(relayId, relayNtorKey);
  assertEquals(clientHandshake.length, 84);
  assertEquals(state.relayIdentity, relayId);
  assertEquals(state.relayNtorOnionKey, relayNtorKey);
});

Deno.test("stream cipher AES-128-CTR roundtrip", () => {
  const key = randomBytes(16);
  const enc = new TorStreamCipher(key);
  const dec = new TorStreamCipher(key);

  const plaintext = new TextEncoder().encode("Hello Tor Network!");
  const ciphertext = enc.process(plaintext);
  const decrypted = dec.process(ciphertext);

  assertEquals(decrypted, plaintext);
});

Deno.test("running digest tracking", () => {
  const seed = randomBytes(20);
  const digest1 = new TorDigest(seed);
  const digest2 = new TorDigest(seed);

  const chunk1 = new TextEncoder().encode("cell-1-payload");
  const tag1 = digest1.updateAndGetTag(chunk1);
  const tag2 = digest2.updateAndGetTag(chunk1);

  assertEquals(tag1, tag2);
  assertEquals(tag1.length, 4);
});
