/**
 * Fetches the v3 Hidden Service descriptor from an HSDir relay over Tor.
 * Uses RELAY_BEGIN_DIR to open an internal directory stream (no exit needed).
 * rend-spec-v3 Section 3.1.
 */
import { TorCircuit } from "../circuit/circuit.ts";
import { CircuitStream } from "../stream/stream.ts";
import { RelayCommand } from "../protocol/constants.ts";
import { HiddenServiceError } from "../common/errors.ts";
import { logger } from "../common/logger.ts";
import { encodeBase64 } from "../crypto/utils.ts";

/**
 * A raw parsed introduction point from a descriptor.
 */
export interface RawIntroPoint {
  /** Link specifier blob for the intro relay */
  linkSpecifiers: Uint8Array;
  /** 32-byte ntor onion key for the introduction relay itself */
  ntorOnionKey: Uint8Array;
  /** 32-byte encryption key for encrypting INTRODUCE1 to the hidden service */
  encKey: Uint8Array;
  /** 32-byte Ed25519 auth key (used as identifier in INTRODUCE1) */
  authKey: Uint8Array;
  /** IP address string */
  ip: string;
  /** OR port */
  port: number;
  /** 20-byte legacy RSA identity */
  legacyId: Uint8Array;
}

/**
 * Open an internal directory stream on a circuit via RELAY_BEGIN_DIR.
 * This doesn't need an exit node — the HSDir relay itself serves the request.
 */
async function beginDirStream(
  circuit: TorCircuit,
  streamId: number,
  timeoutMs: number
): Promise<CircuitStream> {
  const stream = new CircuitStream(streamId, circuit);

  const connectedPromise = new Promise<void>((resolve, reject) => {
    const timer = setTimeout(() => {
      circuit.unregisterStream(streamId);
      reject(new HiddenServiceError("Timeout opening BEGIN_DIR stream"));
    }, timeoutMs);

    circuit.registerStream(streamId, (cell) => {
      if (cell.command === RelayCommand.CONNECTED) {
        clearTimeout(timer);
        circuit.registerStream(streamId, (c) => (stream as any).handleIncomingRelayCell(c));
        resolve();
      } else if (cell.command === RelayCommand.END) {
        clearTimeout(timer);
        reject(new HiddenServiceError("BEGIN_DIR stream refused by HSDir"));
      }
    });
  });

  // RELAY_BEGIN_DIR has an empty payload — it tells the relay to connect internally
  await circuit.sendRelayCell(RelayCommand.BEGIN_DIR, streamId, new Uint8Array(0));
  await connectedPromise;
  return stream;
}

/**
 * Read all data from a stream until it closes.
 */
async function readAll(stream: CircuitStream): Promise<Uint8Array> {
  const chunks: Uint8Array[] = [];
  while (true) {
    const chunk = await stream.read();
    if (chunk === null) break;
    chunks.push(chunk);
  }
  const total = chunks.reduce((s, c) => s + c.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    out.set(c, off);
    off += c.length;
  }
  return out;
}

/**
 * Fetch the raw HS descriptor text from an HSDir over a pre-built Tor circuit.
 * @param circuit 1 or 2-hop circuit ending at the HSDir relay
 * @param descriptorId Base64url-encoded descriptor ID (blinded pubkey)
 * @param streamId Stream ID to allocate
 * @param timeoutMs Timeout in milliseconds
 * @returns Raw descriptor document text
 */
export async function fetchHsDescriptor(
  circuit: TorCircuit,
  descriptorId: Uint8Array,
  streamId: number,
  timeoutMs = 15000
): Promise<string> {
  const descIdB64 = encodeBase64(descriptorId).replace(/=+$/, "");
  const path = `/tor/hs/3/${descIdB64}`;
  logger.debug("HSDIR", `Fetching descriptor: GET ${path}`);

  let stream: CircuitStream;
  try {
    stream = await CircuitStream.openDir(circuit, streamId, timeoutMs);
  } catch (e) {
    throw new HiddenServiceError(`Failed to open BEGIN_DIR stream: ${(e as Error).message}`);
  }

  // Send HTTP GET request for the descriptor
  const httpReq = `GET ${path} HTTP/1.0\r\nHost: 127.0.0.1\r\nAccept: */*\r\n\r\n`;
  await stream.write(new TextEncoder().encode(httpReq));

  const rawBytes = await readAll(stream);
  const rawText = new TextDecoder().decode(rawBytes);

  // Strip HTTP response headers
  const headerEnd = rawText.indexOf("\r\n\r\n");
  if (headerEnd === -1) {
    throw new HiddenServiceError("HSDir returned invalid HTTP response (no header boundary)");
  }

  const statusLine = rawText.split("\r\n")[0];
  if (!statusLine.includes("200")) {
    throw new HiddenServiceError(`HSDir returned non-200 status: ${statusLine.trim()}`);
  }

  const body = rawText.substring(headerEnd + 4);
  logger.debug("HSDIR", `Descriptor fetched: ${body.length} bytes`);
  return body;
}

import { shake256 } from "npm:@noble/hashes@1.4.0/sha3";
import { createDecipheriv } from "node:crypto";

/**
 * Decrypt the superencrypted outer layer and encrypted inner layer of a v3 Hidden Service descriptor.
 * rend-spec-v3 Section 2.5.
 *
 * @param rawDoc Raw descriptor text returned by HSDir
 * @param subcred 32-byte subcredential derived for the current time period
 * @param blindedPk 32-byte blinded public key for the current time period
 * @returns Plaintext inner descriptor layer containing introduction-point blocks
 */
export function decryptDescriptor(
  rawDoc: string,
  subcred: Uint8Array,
  blindedPk: Uint8Array
): string {
  // Extract revision-counter (default: 0 if absent)
  const revMatch = rawDoc.match(/revision-counter\s+(\d+)/);
  const revisionCounter = revMatch ? BigInt(revMatch[1]) : 0n;

  // 1. Superencrypted outer layer
  const match1 = rawDoc.match(/superencrypted\s+-----BEGIN MESSAGE-----\s+([A-Za-z0-9+/=\s]+)\s+-----END MESSAGE-----/);
  if (!match1) return rawDoc;

  const superBlob = decodeBase64Util(match1[1].replace(/\s+/g, ""));
  if (superBlob.length < 48) return rawDoc;

  const salt1 = superBlob.subarray(0, 16);
  const encData1 = superBlob.subarray(16, superBlob.length - 32);

  // secret_input = SECRET_DATA (blindedPk, 32) | subcredential (32) | INT_8(revision_counter) (8)
  const revBuf = new Uint8Array(8);
  new DataView(revBuf.buffer).setBigUint64(0, revisionCounter, false);

  const secretInput = new Uint8Array(32 + 32 + 8);
  secretInput.set(blindedPk, 0);
  secretInput.set(subcred, 32);
  secretInput.set(revBuf, 64);

  // KDF1: SHAKE256(secret_input | salt | "hsdir-superencrypted-data", 80)
  const strSuper = new TextEncoder().encode("hsdir-superencrypted-data");
  const kdfInput1 = new Uint8Array(secretInput.length + salt1.length + strSuper.length);
  kdfInput1.set(secretInput, 0);
  kdfInput1.set(salt1, secretInput.length);
  kdfInput1.set(strSuper, secretInput.length + salt1.length);

  const kdfOut1 = shake256(kdfInput1, { dkLen: 80 });
  const key1 = kdfOut1.subarray(0, 32);
  const iv1 = kdfOut1.subarray(32, 48);

  const dec1 = createDecipheriv("aes-256-ctr", key1, iv1);
  const layer2 = Buffer.concat([dec1.update(encData1), dec1.final()]).toString("utf8");

  // 2. Encrypted inner layer
  const match2 = layer2.match(/encrypted\s+-----BEGIN MESSAGE-----\s+([A-Za-z0-9+/=\s]+)\s+-----END MESSAGE-----/);
  if (!match2) return layer2;

  const encBlob2 = decodeBase64Util(match2[1].replace(/\s+/g, ""));
  if (encBlob2.length < 48) return layer2;

  const salt2 = encBlob2.subarray(0, 16);
  const encData2 = encBlob2.subarray(16, encBlob2.length - 32);

  // KDF2: SHAKE256(secret_input | salt | "hsdir-encrypted-data", 80)
  const strEnc = new TextEncoder().encode("hsdir-encrypted-data");
  const kdfInput2 = new Uint8Array(secretInput.length + salt2.length + strEnc.length);
  kdfInput2.set(secretInput, 0);
  kdfInput2.set(salt2, secretInput.length);
  kdfInput2.set(strEnc, secretInput.length + salt2.length);

  const kdfOut2 = shake256(kdfInput2, { dkLen: 80 });
  const key2 = kdfOut2.subarray(0, 32);
  const iv2 = kdfOut2.subarray(32, 48);

  const dec2 = createDecipheriv("aes-256-ctr", key2, iv2);
  return Buffer.concat([dec2.update(encData2), dec2.final()]).toString("utf8");
}

/**
 * Parse raw introduction points from a decrypted descriptor plaintext.
 * Handles the introduction-point blocks in the inner layer format.
 * rend-spec-v3 Section 2.5.
 */
export function parseIntroductionPoints(descriptorText: string): RawIntroPoint[] {
  const introPoints: RawIntroPoint[] = [];
  // Split by introduction-point blocks
  const blocks = descriptorText.split(/(?=^introduction-point\b)/m);

  for (const block of blocks) {
    if (!block.startsWith("introduction-point")) continue;
    try {
      const ip = parseOneIntroPoint(block);
      if (ip) introPoints.push(ip);
    } catch (_e) {
      // Skip malformed intro point blocks
    }
  }

  return introPoints;
}

function parseOneIntroPoint(block: string): RawIntroPoint | null {
  const lines = block.split("\n").map((l) => l.trim());
  let ntorOnionKey: Uint8Array | null = null;
  let encKey: Uint8Array | null = null;
  let authKey: Uint8Array | null = null;
  let ip = "";
  let port = 0;
  let legacyId = new Uint8Array(20);
  const linkSpecifiers: number[] = [];

  // 1. Parse link specifiers from header line: "introduction-point <base64>"
  const firstLine = lines[0];
  const introHeaderMatch = firstLine.match(/^introduction-point\s+([A-Za-z0-9+/=_-]+)/);
  if (introHeaderMatch) {
    const lsBytes = decodeBase64Util(introHeaderMatch[1]);
    if (lsBytes.length > 0) {
      const count = lsBytes[0];
      let off = 1;
      for (let j = 0; j < count && off < lsBytes.length; j++) {
        const lsType = lsBytes[off];
        const lsLen = lsBytes[off + 1];
        const lsData = lsBytes.subarray(off + 2, off + 2 + lsLen);
        off += 2 + lsLen;

        if (lsType === 0x00 && lsLen === 6) {
          ip = `${lsData[0]}.${lsData[1]}.${lsData[2]}.${lsData[3]}`;
          port = (lsData[4] << 8) | lsData[5];
        } else if (lsType === 0x02 && lsLen === 20) {
          legacyId = new Uint8Array(lsData);
        }

        linkSpecifiers.push(lsType, lsLen, ...lsData);
      }
    }
  }

  // 2. Parse body fields
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith("onion-key ntor ")) {
      const b64 = line.substring("onion-key ntor ".length).trim();
      if (b64) ntorOnionKey = decodeBase64Util(b64);
    } else if (line.startsWith("enc-key ntor ")) {
      const b64 = line.substring("enc-key ntor ".length).trim();
      if (b64) encKey = decodeBase64Util(b64);
    } else if (line.startsWith("auth-key")) {
      const certLines: string[] = [];
      i++;
      while (i < lines.length && !lines[i].startsWith("-----END")) {
        if (!lines[i].startsWith("-----BEGIN")) certLines.push(lines[i]);
        i++;
      }
      const certBytes = decodeBase64Util(certLines.join(""));
      // Ed25519 cert format: VERSION(1) | CERT_TYPE(1) | EXPIRY(4) | KEY_TYPE(1) | CERT_KEY(32)
      if (certBytes.length >= 39) {
        authKey = certBytes.subarray(7, 39);
      }
    } else if (line.startsWith("link-specifiers ")) {
      const b64 = line.substring("link-specifiers ".length).trim();
      const lsBytes = decodeBase64Util(b64);
      if (lsBytes.length > 0) {
        const count = lsBytes[0];
        let off = 1;
        for (let j = 0; j < count && off < lsBytes.length; j++) {
          const lsType = lsBytes[off];
          const lsLen = lsBytes[off + 1];
          const lsData = lsBytes.subarray(off + 2, off + 2 + lsLen);
          off += 2 + lsLen;

          if (lsType === 0x00 && lsLen === 6 && !ip) {
            ip = `${lsData[0]}.${lsData[1]}.${lsData[2]}.${lsData[3]}`;
            port = (lsData[4] << 8) | lsData[5];
          } else if (lsType === 0x02 && lsLen === 20) {
            legacyId = new Uint8Array(lsData);
          }

          linkSpecifiers.push(lsType, lsLen, ...lsData);
        }
      }
    }
  }

  if (!authKey) return null;
  // If encKey is missing, fall back to ntorOnionKey; if ntorOnionKey is missing, fall back to encKey
  if (!ntorOnionKey && encKey) ntorOnionKey = encKey;
  if (!encKey && ntorOnionKey) encKey = ntorOnionKey;
  if (!ntorOnionKey || !encKey) return null;

  return {
    linkSpecifiers: new Uint8Array(linkSpecifiers),
    ntorOnionKey,
    encKey,
    authKey,
    ip,
    port,
    legacyId,
  };
}

function decodeBase64Util(str: string): Uint8Array {
  let b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) b64 += "=";
  return new Uint8Array(Buffer.from(b64, "base64"));
}
