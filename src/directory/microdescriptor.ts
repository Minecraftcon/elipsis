/**
 * Tor Microdescriptor Parser.
 * Extracts ntor-onion-key, ed25519 identity, and exit policies from microdescriptors.
 */
import { decodeBase64 } from "../crypto/utils.ts";

export interface ParsedMicrodescriptor {
  ntorOnionKey?: Uint8Array;
  identityEd25519?: Uint8Array;
  exitPolicyAccept?: string[];
  exitPolicyReject?: string[];
  family?: string[];
}

export function parseMicrodescriptors(text: string): Map<string, ParsedMicrodescriptor> {
  const blocks = text.split(/(?=^onion-key)/m).filter((b) => b.trim().length > 0);
  const result = new Map<string, ParsedMicrodescriptor>();

  for (const block of blocks) {
    if (!block.includes("ntor-onion-key")) continue;

    const lines = block.split("\n");
    const desc: ParsedMicrodescriptor = {};

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (line.startsWith("ntor-onion-key ")) {
        const keyBase64 = line.substring(15).trim();
        try {
          desc.ntorOnionKey = decodeBase64(keyBase64);
        } catch (_e) {}
      } else if (line.startsWith("id ed25519 ")) {
        const keyBase64 = line.substring(11).trim();
        try {
          desc.identityEd25519 = decodeBase64(keyBase64);
        } catch (_e) {}
      } else if (line.startsWith("p accept ")) {
        desc.exitPolicyAccept = line.substring(9).split(",");
      } else if (line.startsWith("p reject ")) {
        desc.exitPolicyReject = line.substring(9).split(",");
      } else if (line.startsWith("family ")) {
        desc.family = line.substring(7).split(" ");
      }
    }

    if (desc.ntorOnionKey) {
      // Key can be identified by ntor key or sha256 digest
      result.set(Buffer.from(desc.ntorOnionKey).toString("base64"), desc);
    }
  }

  return result;
}
