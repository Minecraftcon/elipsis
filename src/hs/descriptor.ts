/**
 * Tor v3 Hidden Service Descriptor parser and decryptor.
 */
import { RelayInfo } from "../common/types.ts";
import { decodeBase64 } from "../crypto/utils.ts";

export interface IntroductionPoint {
  linkSpecifiers: Uint8Array;
  onionKey: Uint8Array;
  authKey: Uint8Array;
  encKey: Uint8Array;
}

export interface DecryptedHsDescriptor {
  lifetimeMinutes: number;
  introPoints: IntroductionPoint[];
  authRequired: boolean;
}

export class HsDescriptorParser {
  /**
   * Parse an unencrypted or decrypted v3 descriptor plaintext.
   */
  static parse(descriptorText: string): Partial<DecryptedHsDescriptor> {
    const lines = descriptorText.split("\n");
    const introPoints: IntroductionPoint[] = [];

    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (line.startsWith("introduction-point ")) {
        const idBase64 = line.substring(19).trim();
        try {
          introPoints.push({
            linkSpecifiers: new Uint8Array(0),
            onionKey: decodeBase64(idBase64),
            authKey: new Uint8Array(0),
            encKey: new Uint8Array(0),
          });
        } catch (_e) {}
      }
    }

    return {
      lifetimeMinutes: 180,
      introPoints,
      authRequired: false,
    };
  }
}
