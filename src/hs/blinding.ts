/**
 * Time period and blinded key calculations for v3 hidden services.
 * Accurately implements Tor C codebase (hs_common.c / crypto_ed25519.c).
 */
import { sha3_256 } from "../crypto/sha3.ts";
import { ed25519 } from "npm:@noble/curves@1.4.0/ed25519";

/** Time period length in minutes (24 hours) */
export const HS_TIME_PERIOD_LENGTH_MINUTES = 1440n;
/** Time period rotation offset in minutes (12 hours) */
export const HS_TIME_PERIOD_ROTATION_OFFSET_MINUTES = 720n;

const BLIND_STR = new TextEncoder().encode("Derive temporary signing key\0");
const ED25519_BASEPOINT_STR = new TextEncoder().encode(
  "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"
);
const KEY_BLIND_PREFIX = new TextEncoder().encode("key-blind");
const STORE_AT_IDX_PREFIX = new TextEncoder().encode("store-at-idx");
const NODE_IDX_PREFIX = new TextEncoder().encode("node-idx");
const CREDENTIAL_PREFIX = new TextEncoder().encode("credential");
const SUBCREDENTIAL_PREFIX = new TextEncoder().encode("subcredential");

/**
 * Compute the current consensus time period number.
 * @param nowMs Current unix timestamp in milliseconds
 * @returns Integer time period number
 */
export function getCurrentTimePeriod(nowMs: number = Date.now()): number {
  const minutesSinceEpoch = BigInt(Math.floor(nowMs / (60 * 1000)));
  const tp = (minutesSinceEpoch - HS_TIME_PERIOD_ROTATION_OFFSET_MINUTES) / HS_TIME_PERIOD_LENGTH_MINUTES;
  return Number(tp);
}

/**
 * Returns true if the current time is between the TP rotation (12:00 UTC) and SRV rotation (00:00 UTC).
 */
export function isBetweenTpAndSrv(nowMs: number = Date.now()): boolean {
  const date = new Date(nowMs);
  const hours = date.getUTCHours();
  // Between 12:00 UTC and 00:00 UTC (i.e. hours 12 to 23)
  return hours >= 12;
}

/**
 * Derive the blinded Ed25519 public key for a hidden service identity key.
 * Corresponds to Tor hs_build_blinded_pubkey and ed25519_public_blind.
 */
export function deriveBlindedPublicKey(publicKey: Uint8Array, timePeriod: number): Uint8Array {
  const periodNum = BigInt(timePeriod);
  const periodLen = HS_TIME_PERIOD_LENGTH_MINUTES;

  // Nonce N = "key-blind" || INT_8(period_num) || INT_8(period_length)
  const nonce = new Uint8Array(9 + 8 + 8);
  nonce.set(KEY_BLIND_PREFIX, 0);
  const view = new DataView(nonce.buffer);
  view.setBigUint64(9, periodNum, false);
  view.setBigUint64(17, periodLen, false);

  // param = H(BLIND_STRING | pubkey | ed25519-basepoint | N)
  const toHash = new Uint8Array(
    BLIND_STR.length + publicKey.length + ED25519_BASEPOINT_STR.length + nonce.length
  );
  let off = 0;
  toHash.set(BLIND_STR, off); off += BLIND_STR.length;
  toHash.set(publicKey, off); off += publicKey.length;
  toHash.set(ED25519_BASEPOINT_STR, off); off += ED25519_BASEPOINT_STR.length;
  toHash.set(nonce, off);

  const param = sha3_256(toHash);

  // Clamping tweak: param[0] &= 248, param[31] &= 63, param[31] |= 64
  const tweak = new Uint8Array(param);
  tweak[0] &= 248;
  tweak[31] &= 63;
  tweak[31] |= 64;

  let tweakScalar = 0n;
  for (let i = tweak.length - 1; i >= 0; i--) {
    tweakScalar = (tweakScalar << 8n) | BigInt(tweak[i]);
  }
  tweakScalar = tweakScalar % ed25519.CURVE.n;

  const A = ed25519.ExtendedPoint.fromHex(
    Array.from(publicKey).map(b => b.toString(16).padStart(2, "0")).join("")
  );
  const Aprime = A.multiply(tweakScalar);
  return Aprime.toRawBytes();
}

/**
 * Derive the subcredential for an identity key and blinded public key.
 * Corresponds to Tor hs_get_subcredential.
 */
export function deriveSubcredential(publicKey: Uint8Array, blindedPublicKey: Uint8Array): Uint8Array {
  // credential = H("credential" | public-identity-key)
  const credBuf = new Uint8Array(CREDENTIAL_PREFIX.length + publicKey.length);
  credBuf.set(CREDENTIAL_PREFIX, 0);
  credBuf.set(publicKey, CREDENTIAL_PREFIX.length);
  const credential = sha3_256(credBuf);

  // subcredential = H("subcredential" | credential | blinded-public-key)
  const subcredBuf = new Uint8Array(SUBCREDENTIAL_PREFIX.length + credential.length + blindedPublicKey.length);
  let off = 0;
  subcredBuf.set(SUBCREDENTIAL_PREFIX, off); off += SUBCREDENTIAL_PREFIX.length;
  subcredBuf.set(credential, off); off += credential.length;
  subcredBuf.set(blindedPublicKey, off);

  return sha3_256(subcredBuf);
}

/**
 * Build hs_index for selecting responsible HSDirs.
 * Corresponds to Tor hs_build_hs_index.
 */
export function buildHsIndex(replica: number, blindedPublicKey: Uint8Array, timePeriod: number): Uint8Array {
  const periodNum = BigInt(timePeriod);
  const periodLen = HS_TIME_PERIOD_LENGTH_MINUTES;

  const buf = new Uint8Array(STORE_AT_IDX_PREFIX.length + 32 + 8 + 8 + 8);
  let off = 0;
  buf.set(STORE_AT_IDX_PREFIX, off); off += STORE_AT_IDX_PREFIX.length;
  buf.set(blindedPublicKey, off); off += 32;
  const view = new DataView(buf.buffer);
  view.setBigUint64(off, BigInt(replica), false); off += 8;
  view.setBigUint64(off, periodLen, false); off += 8;
  view.setBigUint64(off, periodNum, false);

  return sha3_256(buf);
}

/**
 * Build hsdir_index for indexing relay positions in the HSDir hash ring.
 * Corresponds to Tor hs_build_hsdir_index.
 */
export function buildHsdirIndex(identityEd25519: Uint8Array, srvValue: Uint8Array, timePeriod: number): Uint8Array {
  const periodNum = BigInt(timePeriod);
  const periodLen = HS_TIME_PERIOD_LENGTH_MINUTES;

  const buf = new Uint8Array(NODE_IDX_PREFIX.length + 32 + 32 + 8 + 8);
  let off = 0;
  buf.set(NODE_IDX_PREFIX, off); off += NODE_IDX_PREFIX.length;
  buf.set(identityEd25519, off); off += 32;
  buf.set(srvValue, off); off += 32;
  const view = new DataView(buf.buffer);
  view.setBigUint64(off, periodNum, false); off += 8;
  view.setBigUint64(off, periodLen, false);

  return sha3_256(buf);
}
