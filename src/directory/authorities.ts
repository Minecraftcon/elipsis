/**
 * Hardcoded Tor Directory Authorities and Fallback Directory Mirrors.
 */
import { RelayInfo } from "../common/types.ts";
import { decodeBase64, decodeHex } from "../crypto/utils.ts";

/**
 * Metadata defining a trusted Tor Directory Authority.
 */
export interface DirectoryAuthority {
  /** Authority nickname */
  nickname: string;
  /** IPv4 address */
  ip: string;
  /** Onion routing port */
  orPort: number;
  /** Directory mirror HTTP port */
  dirPort: number;
  /** v3 identity key fingerprint in hex */
  v3IdentHex: string;
  /** Legacy RSA identity fingerprint in hex */
  identityRsaHex: string;
}

/**
 * Official Tor Directory Authorities (tor-spec Section 0.2 / default dirauths)
 */
export const DIRECTORY_AUTHORITIES: DirectoryAuthority[] = [
  {
    nickname: "bastet",
    ip: "204.13.164.118",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "27102BE3D01407381D50DF707026A9ED3F3A6E77",
    identityRsaHex: "24BAB2F7EB78D00B224F1D479E163E08BCAC03F3",
  },
  {
    nickname: "dannenberg",
    ip: "193.23.244.244",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "0232AF901C31A04EE9848595AF9BB7620D4C5B2E",
    identityRsaHex: "7BE683E65D48141321C5ED92F075C55364AC7123",
  },
  {
    nickname: "maatuska",
    ip: "171.25.193.9",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "49015F78743003FD10226383ED1069E5030A1E16",
    identityRsaHex: "BD44A889E2921813BC1939A4684DBC540EDEB21A",
  },
  {
    nickname: "Faravahar",
    ip: "154.35.175.225",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "EFCBE72040D3CF660F32B81137D80E4B705E0826",
    identityRsaHex: "CF6D0AAFB385BE71B8E111C2C9BA9384F38D930E",
  },
  {
    nickname: "Longclaw",
    ip: "199.58.81.140",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "23D15D965BC351144F8677B2025D94A3E9548032",
    identityRsaHex: "74A910646BCEEF88C14F656492D417A320A241C6",
  },
];

/**
 * Fast Fallback Directory Relays (used for immediate bootstrapping and consensus download).
 */
export const DEFAULT_FALLBACK_RELAYS: RelayInfo[] = [
  {
    nickname: "skylarkRelay",
    ip: "95.111.230.178",
    orPort: 443,
    dirPort: 80,
    identityRsa: decodeHex("00240ecb2b535aa4c1e1874d744dfa6af2e5e941"),
    identityEd25519: decodeBase64("uZ0YqbYpBJ8Ts8lomKs8PRlxPFucUJFayt/pWGilkd0="),
    ntorOnionKey: decodeBase64("h2u6UpJBRswuTixIhNfeyMCC7Hh6f57VHntn+jE6CTk="),
    flags: new Set(["Fast", "Guard", "HSDir", "Running", "Stable", "V2Dir", "Valid"]),
  },
  {
    nickname: "SENDNOOSEplz",
    ip: "204.137.14.106",
    orPort: 443,
    dirPort: 80,
    identityRsa: decodeHex("000f3eb75342be371f1d8d3fae90890aeb5664ee"),
    identityEd25519: decodeBase64("EqqGIPqix6vuREOrXnvvWP3LHHrHlpeT6puR386eGq8="),
    ntorOnionKey: decodeBase64("M8NEbew4uedY3uBkO6ghHX9DGIa6bmOjmPT3cJRauQs="),
    flags: new Set(["Exit", "Fast", "Guard", "Running", "Stable", "V2Dir", "Valid"]),
  },
  {
    nickname: "titamon3",
    ip: "178.218.144.18",
    orPort: 443,
    dirPort: 80,
    identityRsa: decodeHex("0011254cc8444369b20ef11156b8990438221a54"),
    identityEd25519: decodeBase64("HRO7+ViQx2dAJKGN074r3PGyB/+MRj1pVaOpk1u85SU="),
    ntorOnionKey: decodeBase64("5bEq2TlAeTHPtJKZYdCk+lm9zTHYDBgM/hGXvoTLA0s="),
    flags: new Set(["Exit", "Fast", "Guard", "Running", "Stable", "V2Dir", "Valid"]),
  },
];

