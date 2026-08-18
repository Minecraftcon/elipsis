/**
 * Tor link specifiers encoding and decoding for EXTEND2 cells (Section 5.1.2).
 */
import { BufferReader, BufferWriter } from "../common/buffer_reader.ts";
import { LinkSpecifierType } from "./constants.ts";

export interface LinkSpecifier {
  type: LinkSpecifierType;
  data: Uint8Array;
}

export function createIPv4LinkSpecifier(ip: string, port: number): LinkSpecifier {
  const parts = ip.split(".").map((p) => parseInt(p, 10));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    throw new Error(`Invalid IPv4 address: ${ip}`);
  }

  const buf = new Uint8Array(6);
  buf.set(parts, 0);
  buf[4] = (port >> 8) & 0xff;
  buf[5] = port & 0xff;

  return {
    type: LinkSpecifierType.TLS_OVER_IPV4,
    data: buf,
  };
}

export function createLegacyIdLinkSpecifier(rsaFingerprint: Uint8Array): LinkSpecifier {
  if (rsaFingerprint.length !== 20) {
    throw new Error(`Legacy RSA identity must be 20 bytes, got ${rsaFingerprint.length}`);
  }
  return {
    type: LinkSpecifierType.LEGACY_IDENTITY,
    data: rsaFingerprint,
  };
}

export function createEd25519LinkSpecifier(ed25519Pub: Uint8Array): LinkSpecifier {
  if (ed25519Pub.length !== 32) {
    throw new Error(`Ed25519 identity must be 32 bytes, got ${ed25519Pub.length}`);
  }
  return {
    type: LinkSpecifierType.ED25519_IDENTITY,
    data: ed25519Pub,
  };
}

export function encodeLinkSpecifiers(specifiers: LinkSpecifier[]): Uint8Array {
  const writer = new BufferWriter();
  writer.writeUint8(specifiers.length);

  for (const spec of specifiers) {
    writer.writeUint8(spec.type);
    writer.writeUint8(spec.data.length);
    writer.writeBytes(spec.data);
  }

  return writer.toUint8Array();
}

export function decodeLinkSpecifiers(reader: BufferReader): LinkSpecifier[] {
  const count = reader.readUint8();
  const specifiers: LinkSpecifier[] = [];

  for (let i = 0; i < count; i++) {
    const type = reader.readUint8();
    const len = reader.readUint8();
    const data = reader.readBytes(len);
    specifiers.push({ type, data });
  }

  return specifiers;
}
