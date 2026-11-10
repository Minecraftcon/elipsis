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
 * Official Tor Directory Authorities (tor-spec Section 0.2 / auth_dirs.inc).
 * These are long-term, trusted servers maintained by the Tor project that
 * publish the hourly network status consensus.
 */
export const DIRECTORY_AUTHORITIES: DirectoryAuthority[] = [
  {
    nickname: "moria1",
    ip: "128.31.0.39",
    orPort: 9201,
    dirPort: 9231,
    v3IdentHex: "F533C81CEF0BC0267857C99B2F471ADF249FA232",
    identityRsaHex: "1A25C6358DB91342AA51720A5038B72742732498",
  },
  {
    nickname: "tor26",
    ip: "217.196.147.77",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C",
    identityRsaHex: "FAA4BCA4A6AC0FB4CA2F8AD5A11D9E122BA894F6",
  },
  {
    nickname: "dizum",
    ip: "45.66.35.11",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58",
    identityRsaHex: "7EA6EAD6FD83083C538F44038BBFA077587DD755",
  },
  {
    nickname: "gabelmoo",
    ip: "131.188.40.189",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "ED03BB616EB2F60BEC80151114BB25CEF515B226",
    identityRsaHex: "F2044413DAC2E02E3D6BCF4735A19BCA1DE97281",
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
    orPort: 80,
    dirPort: 443,
    v3IdentHex: "49015F787433103580E3B66A1707A00E60F2D15B",
    identityRsaHex: "BD6A829255CB08E66FBE7D3748363586E46B3810",
  },
  {
    nickname: "longclaw",
    ip: "199.58.81.140",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "23D15D965BC35114467363C165C4F724B64B4F66",
    identityRsaHex: "74A910646BCEEFBCD2E874FC1DC997430F968145",
  },
  {
    nickname: "faravahar",
    ip: "216.218.219.41",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "70849B868D606BAECFB6128C5E3D782029AA394F",
    identityRsaHex: "E3E42D35F801C9D5AB23584E0025D56FE2B33396",
  },
  {
    nickname: "bastet",
    ip: "204.13.164.118",
    orPort: 443,
    dirPort: 80,
    v3IdentHex: "27102BE3D01407381D50DF707026A9ED3F3A6E77",
    identityRsaHex: "24BAB2F7EB78D00B224F1D479E163E08BCAC03F3",
  },
];

/**
 * Fallback Directory Relays (from official Tor consensus / fallback_dirs.inc).
 * Used only as emergency bootstrap seeds if directory authorities or local cache are unreachable.
 */
export const DEFAULT_FALLBACK_RELAYS: RelayInfo[] = [
  {
    nickname: "SENDNOOSEplz",
    ip: "204.137.14.106",
    orPort: 443,
    identityRsa: decodeHex("000f3eb75342be371f1d8d3fae90890aeb5664ee"),
    identityEd25519: decodeBase64("EqqGIPqix6vuREOrXnvvWP3LHHrHlpeT6puR386eGq8"),
    ntorOnionKey: decodeBase64("HJE5xIi8eyb8cMAv9/jCbmtu3MOo7udfNkk88ueb9R0="),
    flags: new Set(["Fast", "Guard", "Running", "Stable", "Valid"]),
  },
  {
    nickname: "titamon3",
    ip: "178.218.144.18",
    orPort: 443,
    identityRsa: decodeHex("0011254cc8444369b20ef11156b8990438221a54"),
    identityEd25519: decodeBase64("HRO7+ViQx2dAJKGN074r3PGyB/+MRj1pVaOpk1u85SU="),
    ntorOnionKey: decodeBase64("vH63mdfWHih+zmGvLVpMCHBiF74a7LtRH222wbM9Bhw="),
    flags: new Set(["Fast", "Guard", "Running", "Stable", "Valid"]),
  },
  {
    nickname: "masterp",
    ip: "96.9.98.148",
    orPort: 443,
    identityRsa: decodeHex("0024fbf8aa8ece3bac3e0c4383955c4bdd2b9866"),
    identityEd25519: decodeBase64("FoHHQW1PWaGB01bncOe74/1kDwAJKdQTUXro/3wPpoY="),
    ntorOnionKey: decodeBase64("Uu4UC+dJSxbDDIV2phfWI7C0ErsO5mrbF8b4KiGXFUc="),
    flags: new Set(["Fast", "Guard", "Running", "Stable", "Valid"]),
  },
  {
    nickname: "ernies",
    ip: "80.239.189.84",
    orPort: 9001,
    identityRsa: decodeHex("0028c91cfba3601f32f90ef9643bef5ed031a658"),
    identityEd25519: decodeBase64("LpocaDlIc67UffNSkSYI3PN/T6ZxdNTNPwwNEy8zzo0="),
    ntorOnionKey: decodeBase64("0Js1dvauNU+9YqTNg8Tdu7JxS+TLM5hX9mznnwq02Uk="),
    flags: new Set(["Fast", "Guard", "Running", "Stable", "Valid"]),
  },
  {
    nickname: "chali2na",
    ip: "64.65.62.145",
    orPort: 443,
    identityRsa: decodeHex("0040e1791755d340ba8109f4c1849666582cf56c"),
    identityEd25519: decodeBase64("9oUiNY4JNJhpCZr+bXrPv9ygmOd2TpakVaq2K7Yc0Xo="),
    ntorOnionKey: decodeBase64("2VQnI1DcTLjIRh2w6rn5yqoFIy6DL5Ff6upThmI8Bxc="),
    flags: new Set(["Fast", "Guard", "Running", "Stable", "Valid"]),
  },
];

