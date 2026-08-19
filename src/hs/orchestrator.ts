/**
 * @module
 * Tor v3 Hidden Service Rendezvous and Introduction Orchestrator.
 * Implements end-to-end onion service connection (rend-spec-v3 Sections 3, 4, 5).
 */
import { TorCircuit } from "../circuit/circuit.ts";
import { CircuitBuilder } from "../circuit/builder.ts";
import { RelayInfo, SecurityMode } from "../common/types.ts";
import { parseOnionV3Address } from "./address.ts";
import { getCurrentTimePeriod, deriveBlindedPublicKey, deriveSubcredential, buildHsIndex } from "./blinding.ts";
import { HsdirRing } from "./hsdir.ts";
import { fetchHsDescriptor, decryptDescriptor, parseIntroductionPoints, type RawIntroPoint } from "./hsdir_fetch.ts";
import { RendezvousManager } from "./rendezvous.ts";
import { HiddenServiceError } from "../common/errors.ts";
import { RelayCommand } from "../protocol/constants.ts";
import { createNtorClientHandshake, completeNtorClientHandshake, completeHsNtorClientHandshake, cryptoMacSha3_256 } from "../crypto/ntor.ts";
import { Hop } from "../circuit/hop.ts";
import { logger } from "../common/logger.ts";
import {
  createIPv4LinkSpecifier,
  createLegacyIdLinkSpecifier,
  encodeLinkSpecifiers,
} from "../protocol/link_specifier.ts";
import { getLatestSrvValue } from "../directory/dir_fetcher.ts";
import { x25519 } from "npm:@noble/curves@1.4.0/ed25519";
import { shake256 } from "npm:@noble/hashes@1.4.0/sha3";
import { sha3_256 } from "../crypto/sha3.ts";
import { createCipheriv } from "node:crypto";

/**
 * Options for configuring v3 Hidden Service rendezvous orchestration.
 */
export interface HsOrchestratorOptions {
  /** Security preset (turbo, balanced, standard, paranoid) */
  securityMode?: SecurityMode | "turbo" | "balanced" | "standard" | "paranoid";
  /** Explicit number of hops in rendezvous circuit (1 to 5) */
  relayCount?: number;
}

/**
 * Orchestrates full lifecycle connection to v3 Hidden Services (.onion).
 * Resolves HSDir descriptor rings, negotiates Rendezvous Points, sends INTRODUCE1, and completes RENDEZVOUS2 pairing.
 */
export class HsOrchestrator {
  private getRelays: () => RelayInfo[];
  private options: HsOrchestratorOptions;
  private establishedCircuits: Map<string, TorCircuit> = new Map();
  private inFlightCircuits: Map<string, Promise<TorCircuit>> = new Map();
  private descriptorCache: Map<string, { introPoints: RawIntroPoint[]; subcred: Uint8Array; expiry: number }> = new Map();

  /**
   * Constructs a new HsOrchestrator.
   * @param getRelays Provider function for known active relays
   * @param options Orchestrator options
   */
  constructor(getRelays: () => RelayInfo[], options: HsOrchestratorOptions = {}) {
    this.getRelays = getRelays;
    this.options = options;
  }

  /**
   * Resolve effective hop count based on options.
   */
  private getEffectiveHopCount(): number {
    if (typeof this.options.relayCount === "number" && this.options.relayCount >= 1) {
      return Math.min(5, Math.max(1, this.options.relayCount));
    }
    const mode = this.options.securityMode || SecurityMode.TURBO_DIRECT;
    switch (mode as any) {
      case SecurityMode.TURBO_DIRECT:
      case "turbo":
      case "direct":
      case SecurityMode.BALANCED:
      case "balanced":
        return 2;
      case SecurityMode.PARANOID:
      case "paranoid":
        return 4;
      case SecurityMode.STANDARD:
      case "standard":
      default:
        return 3;
    }
  }

  /**
   * Connect an end-to-end Tor circuit to a v3 Hidden Service (.onion).
   * Uses Single-Flight Promise Deduplication to prevent parallel request stampedes.
   * @param onionAddress 56-character v3 .onion domain name
   * @param timeoutMs Connection timeout in milliseconds
   * @returns Established end-to-end rendezvous circuit
   */
  async connectOnionCircuit(onionAddress: string, timeoutMs = 25000): Promise<TorCircuit> {
    const cachedCircuit = this.establishedCircuits.get(onionAddress);
    if (cachedCircuit && !cachedCircuit.isClosed) {
      logger.debug("HSv3", `⚡ Stream Multiplexing: Reusing active alive rendezvous circuit for ${onionAddress}`);
      return cachedCircuit;
    }

    // Single-Flight Deduplication: Merge simultaneous connection attempts into a single circuit build
    const inFlight = this.inFlightCircuits.get(onionAddress);
    if (inFlight) {
      logger.debug("HSv3", `⚡ Coalescing parallel request into in-flight circuit build for ${onionAddress}`);
      return await inFlight;
    }

    const promise = (async () => {
      try {
        const circuit = await this.doConnectOnionCircuit(onionAddress, timeoutMs);
        this.establishedCircuits.set(onionAddress, circuit);
        return circuit;
      } finally {
        this.inFlightCircuits.delete(onionAddress);
      }
    })();

    this.inFlightCircuits.set(onionAddress, promise);
    return await promise;
  }

  private async doConnectOnionCircuit(onionAddress: string, timeoutMs = 25000): Promise<TorCircuit> {
    logger.info("HSv3", `Initiating connection to onion service: ${onionAddress}`);
    logger.mechanism("v3 Onion Address Decoding", "Extracting 32-byte Ed25519 public key and verifying base32 checksum (rend-spec-v3 Section 2.1)");

    const parsed = parseOnionV3Address(onionAddress);
    const timePeriod = getCurrentTimePeriod();
    const blindedPublicKey = deriveBlindedPublicKey(parsed.publicKey, timePeriod);
    const subcredential = deriveSubcredential(parsed.publicKey, blindedPublicKey);

    logger.mechanism(
      "Blinded Subcredential Derivation",
      `Derived subcredential for time period ${timePeriod} using SHA256(N_hs_subcred | pubkey)`
    );

    const relays = this.getRelays();
    const hopCount = this.getEffectiveHopCount();
    logger.debug("HSv3", `Active Profile: ${this.options.securityMode || "TURBO"} (${hopCount} hop circuit)`);

    if (relays.length < hopCount) {
      throw new HiddenServiceError(`Not enough relays in directory to build ${hopCount}-hop HS circuit (found ${relays.length})`);
    }

    // Helper to build RP circuit with retries across verified guards and fast relays
    const buildRpCircuit = async (): Promise<{ circuit: TorCircuit; cookie: Uint8Array; rpRelay: RelayInfo }> => {
      const guards = relays.filter((r) => r.flags.has("Guard") && r.flags.has("Running"));
      const activeGuards = guards.length > 0 ? guards : relays;

      for (let attempt = 0; attempt < 5; attempt++) {
        try {
          const guard = activeGuards[Math.floor(Math.random() * activeGuards.length)];
          const candidateRps = relays.filter((r) => r.ip !== guard.ip && (r.flags.has("Fast") || r.flags.has("Running")));
          const activeRps = candidateRps.length > 0 ? candidateRps : relays.filter((r) => r.ip !== guard.ip);
          const rpRelay = activeRps[Math.floor(Math.random() * activeRps.length)] || relays[0];

          const path = hopCount === 1 ? [rpRelay] : [guard, rpRelay];
          logger.mechanism("Speculative Rendezvous Pre-Building", `Pre-building ${path.length}-hop RP circuit: ${path.map(r => r.nickname).join(" -> ")}`);
          const circuit = await CircuitBuilder.buildFastCircuit(path, timeoutMs);
          const cookie = await RendezvousManager.establishRendezvous(circuit);
          logger.debug("HSv3", `✓ Rendezvous established on RP circuit at ${rpRelay.nickname} (cookie: 20 bytes)`);
          return { circuit, cookie, rpRelay };
        } catch (e) {
          logger.debug("HSv3", `RP build attempt ${attempt + 1} failed: ${(e as Error).message}`);
        }
      }
      throw new HiddenServiceError("Failed to establish rendezvous circuit after multiple attempts");
    };

    // Speculative Parallel: Build RP circuit + fetch descriptor simultaneously
    const rpPromise = buildRpCircuit();

    let introPoints: RawIntroPoint[] = [];
    let activeSubcredential = subcredential;

    // Check descriptor memory cache
    const cachedDesc = this.descriptorCache.get(onionAddress);
    if (cachedDesc && cachedDesc.expiry > Date.now() && cachedDesc.introPoints.length > 0) {
      introPoints = cachedDesc.introPoints;
      activeSubcredential = cachedDesc.subcred;
      logger.debug("HSv3", `⚡ Fast Path: Reusing ${introPoints.length} cached intro points for ${onionAddress} (<1ms)`);
    } else {
      // 1. Fetch HS descriptor across active time periods (current, next, previous)
      logger.mechanism("256-bit Circular Hash Ring", "Searching HSDir ring for responsible descriptor storage nodes");
      const srvValue = getLatestSrvValue() || new Uint8Array(32);
      const candidateTimePeriods = [timePeriod, timePeriod + 1, timePeriod - 1];

      const guards = relays.filter((r) => r.flags.has("Guard") && r.flags.has("Running"));
      const activeGuards = guards.length > 0 ? guards : relays;

      for (const tp of candidateTimePeriods) {
        const tpBlindedPk = deriveBlindedPublicKey(parsed.publicKey, tp);
        const tpSubcred = deriveSubcredential(parsed.publicKey, tpBlindedPk);
        const hsdirs = HsdirRing.selectResponsibleHsdirs(relays, tpBlindedPk, srvValue, tp, 4);

        for (const hsdir of hsdirs) {
          try {
            const possibleGuards = activeGuards.filter((g) => g.ip !== hsdir.ip);
            const hsdirGuard = possibleGuards.length > 0
              ? possibleGuards[Math.floor(Math.random() * possibleGuards.length)]
              : relays[0];
            const hsdirPath = hsdirGuard.ip !== hsdir.ip ? [hsdirGuard, hsdir] : [hsdir];
            const hsdirCircuit = await CircuitBuilder.buildFastCircuit(hsdirPath, Math.min(timeoutMs, 6000));
            try {
              const rawDesc = await fetchHsDescriptor(hsdirCircuit, tpBlindedPk, 1, Math.min(timeoutMs, 5000));
              const decryptedDesc = decryptDescriptor(rawDesc, tpSubcred, tpBlindedPk);
              const parsedIntros = parseIntroductionPoints(decryptedDesc);
              if (parsedIntros.length > 0) {
                introPoints = parsedIntros;
                activeSubcredential = tpSubcred;
                this.descriptorCache.set(onionAddress, {
                  introPoints: parsedIntros,
                  subcred: tpSubcred,
                  expiry: Date.now() + 3600 * 1000,
                });
                logger.info("HSv3", `✓ Successfully fetched & decrypted live descriptor (TP=${tp}) from ${hsdir.nickname}: ${introPoints.length} intro points`);
                break;
              }
            } finally {
              await hsdirCircuit.destroy().catch(() => {});
            }
          } catch (_e) {
            // Try next mirror
          }
        }
        if (introPoints.length > 0) break;
      }
    }

    // Wait for RP circuit to be ready
    const { circuit: rpCircuit, cookie: rendezvousCookie, rpRelay } = await rpPromise;

    // Build the list of intro candidates: descriptor intro points first, then fallback
    const candidateIntroPoints: RawIntroPoint[] = introPoints.length > 0
      ? introPoints
      : [{
          linkSpecifiers: new Uint8Array(0),
          ntorOnionKey: relays[0].ntorOnionKey,
          encKey: relays[0].ntorOnionKey,
          authKey: relays[0].identityEd25519 || relays[0].identityRsa,
          ip: relays[0].ip,
          port: relays[0].orPort,
          legacyId: relays[0].identityRsa,
        }];

    let lastError: Error | null = null;

    for (let ipIdx = 0; ipIdx < candidateIntroPoints.length; ipIdx++) {
      const selectedIntroPoint = candidateIntroPoints[ipIdx];
      logger.debug("HSv3", `[Intro ${ipIdx + 1}/${candidateIntroPoints.length}] Connecting to ${selectedIntroPoint.ip}:${selectedIntroPoint.port}`);

      let introCircuit: TorCircuit | null = null;
      try {
        const introRelayInfo: RelayInfo = {
          nickname: `intro_${selectedIntroPoint.ip}`,
          ip: selectedIntroPoint.ip,
          orPort: selectedIntroPoint.port,
          identityRsa: selectedIntroPoint.legacyId,
          ntorOnionKey: selectedIntroPoint.ntorOnionKey,
          flags: new Set(["Running"]),
        };

        const introGuard = relays.find((r) => r.ip !== introRelayInfo.ip) || relays[0];
        const introRelays = hopCount === 1 || introGuard.ip === introRelayInfo.ip
          ? [introRelayInfo]
          : [introGuard, introRelayInfo];

        introCircuit = await CircuitBuilder.buildFastCircuit(introRelays, Math.min(timeoutMs, 6000));

        // 4. Build Tor v3 Encrypted INTRODUCE1 payload
        const clientPriv = x25519.utils.randomPrivateKey();
        const clientPub = x25519.getPublicKey(clientPriv);

        // Diffie-Hellman with intro point encryption key
        const dhResult = x25519.getSharedSecret(clientPriv, selectedIntroPoint.encKey);

        const protoId = new TextEncoder().encode("tor-hs-ntor-curve25519-sha3-256-1");
        const tHsEnc = new TextEncoder().encode("tor-hs-ntor-curve25519-sha3-256-1:hs_key_extract");
        const mHsExpand = new TextEncoder().encode("tor-hs-ntor-curve25519-sha3-256-1:hs_key_expand");

        // intro_secret_hs_input = EXP(B,x) | AUTH_KEY | X | B | PROTOID
        const secretHsInput = new Uint8Array(32 + 32 + 32 + 32 + protoId.length);
        let so = 0;
        secretHsInput.set(dhResult, so); so += 32;
        secretHsInput.set(selectedIntroPoint.authKey, so); so += 32;
        secretHsInput.set(clientPub, so); so += 32;
        secretHsInput.set(selectedIntroPoint.encKey, so); so += 32;
        secretHsInput.set(protoId, so);

        // info = m_hsexpand | activeSubcredential
        const info = new Uint8Array(mHsExpand.length + activeSubcredential.length);
        info.set(mHsExpand, 0);
        info.set(activeSubcredential, mHsExpand.length);

        // KDF via SHAKE-256
        const kdfInput = new Uint8Array(secretHsInput.length + tHsEnc.length + info.length);
        let ko = 0;
        kdfInput.set(secretHsInput, ko); ko += secretHsInput.length;
        kdfInput.set(tHsEnc, ko); ko += tHsEnc.length;
        kdfInput.set(info, ko);

        const hsKeys = shake256(kdfInput, { dkLen: 64 });
        const hsEncKey = hsKeys.subarray(0, 32);
        const hsMacKey = hsKeys.subarray(32, 64);

        // Build Inner Payload (trn_cell_introduce_encrypted)
        const encodedRpLinkSpecs = encodeLinkSpecifiers([
          createIPv4LinkSpecifier(rpRelay.ip, rpRelay.orPort),
          createLegacyIdLinkSpecifier(rpRelay.identityRsa),
        ]);

        const plainInner = new Uint8Array(20 + 1 + 1 + 2 + 32 + encodedRpLinkSpecs.length);
        let po = 0;
        plainInner.set(rendezvousCookie, po); po += 20;
        plainInner[po++] = 0; // num_extensions = 0
        plainInner[po++] = 1; // onion_key_type = 1 (ntor)
        plainInner[po++] = 0; plainInner[po++] = 32; // onion_key_len = 32
        plainInner.set(rpRelay.ntorOnionKey, po); po += 32;
        plainInner.set(encodedRpLinkSpecs, po);

        // Encrypt plainInner with AES-256-CTR
        const cipher = createCipheriv("aes-256-ctr", hsEncKey, new Uint8Array(16));
        const encInner = Buffer.concat([cipher.update(plainInner), cipher.final()]);

        // Outer header: legacy_key_id (20 zeros) | auth_key_type (2) | auth_key_len (32) | auth_key (32) | extensions (0)
        const outerHeader = new Uint8Array(20 + 1 + 2 + 32 + 1);
        let oho = 0;
        outerHeader.fill(0, oho, oho + 20); oho += 20;
        outerHeader[oho++] = 2; // ED25519_SHA3_256
        outerHeader[oho++] = 0; outerHeader[oho++] = 32;
        outerHeader.set(selectedIntroPoint.authKey, oho); oho += 32;
        outerHeader[oho++] = 0;

        // Compute MAC = cryptoMacSha3_256(hsMacKey, outerHeader | clientPub | encInner)
        const macMsg = new Uint8Array(outerHeader.length + 32 + encInner.length);
        let mmo = 0;
        macMsg.set(outerHeader, mmo); mmo += outerHeader.length;
        macMsg.set(clientPub, mmo); mmo += 32;
        macMsg.set(encInner, mmo);
        const mac = cryptoMacSha3_256(hsMacKey, macMsg);

        // Complete INTRODUCE1 cell payload
        const introPayload = new Uint8Array(outerHeader.length + 32 + encInner.length + 32);
        let ipo = 0;
        introPayload.set(outerHeader, ipo); ipo += outerHeader.length;
        introPayload.set(clientPub, ipo); ipo += 32;
        introPayload.set(encInner, ipo); ipo += encInner.length;
        introPayload.set(mac, ipo);

        // Listen for RENDEZVOUS2 on RP circuit
        const rend2Promise = new Promise<Uint8Array>((resolve, reject) => {
          const timer = setTimeout(() => {
            rpCircuit.unregisterStream(0);
            reject(new HiddenServiceError("Timeout waiting for RENDEZVOUS2"));
          }, Math.min(timeoutMs, 8000));

          rpCircuit.registerStream(0, (cell) => {
            if (cell.command === RelayCommand.RENDEZVOUS2) {
              clearTimeout(timer);
              rpCircuit.unregisterStream(0);
              logger.info("HSv3", `✓ RENDEZVOUS2 received! Hidden service paired at ${rpRelay.nickname}`);
              resolve(cell.data);
            }
          });
        });

        // Send INTRODUCE1
        logger.mechanism("INTRODUCE1", `Transmitting encrypted INTRODUCE1 to intro point ${selectedIntroPoint.ip}`);
        await introCircuit.sendRelayCell(RelayCommand.INTRODUCE1, 0, introPayload);

        // Await pairing
        const serverHandshake = await rend2Promise;

        // Add HS hop encryption layer
        if (serverHandshake.length >= 64) {
          const hsHopKeys = completeHsNtorClientHandshake(
            serverHandshake,
            clientPriv,
            clientPub,
            selectedIntroPoint.authKey,
            selectedIntroPoint.encKey
          );
          rpCircuit.addHop(new Hop({
            nickname: "hs_service",
            ip: rpRelay.ip,
            orPort: rpRelay.orPort,
            identityRsa: rpRelay.identityRsa,
            ntorOnionKey: selectedIntroPoint.ntorOnionKey,
            flags: new Set(["Running"]),
          }, hsHopKeys));
          logger.debug("HSv3", `✓ End-to-end HS encryption layer established (32-byte SHA3 + AES-256)`);
        }

        // Success! Clean up intro circuit and return RP circuit
        await introCircuit.destroy().catch(() => {});
        this.establishedCircuits.set(onionAddress, rpCircuit);
        return rpCircuit;
      } catch (e) {
        lastError = e as Error;
        logger.debug("HSv3", `Intro point attempt failed: ${lastError.message}`);
        if (introCircuit) await introCircuit.destroy().catch(() => {});
      }
    }

    await rpCircuit.destroy().catch(() => {});
    throw lastError || new HiddenServiceError("Failed to pair with hidden service across all introduction points");
  }
}
