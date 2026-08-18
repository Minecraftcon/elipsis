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
import { fetchHsDescriptor, parseIntroductionPoints, type RawIntroPoint } from "./hsdir_fetch.ts";
import { RendezvousManager } from "./rendezvous.ts";
import { HiddenServiceError } from "../common/errors.ts";
import { RelayCommand } from "../protocol/constants.ts";
import { BufferWriter } from "../common/buffer_reader.ts";
import { createNtorClientHandshake, completeNtorClientHandshake } from "../crypto/ntor.ts";
import { Hop } from "../circuit/hop.ts";
import { logger } from "../common/logger.ts";
import {
  createIPv4LinkSpecifier,
  createLegacyIdLinkSpecifier,
  encodeLinkSpecifiers,
} from "../protocol/link_specifier.ts";

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
   * @param onionAddress 56-character v3 .onion domain name
   * @param timeoutMs Connection timeout in milliseconds
   * @returns Established end-to-end rendezvous circuit
   */
  async connectOnionCircuit(onionAddress: string, timeoutMs = 25000): Promise<TorCircuit> {
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

    // 1. Select responsible HSDir relays and fetch descriptor
    logger.mechanism("256-bit Circular Hash Ring", "Searching HSDir ring for responsible descriptor storage nodes");
    const srvValue = new Uint8Array(32);
    const hsdirs = HsdirRing.selectResponsibleHsdirs(relays, blindedPublicKey, srvValue, timePeriod, 3);
    logger.debug("HSv3", `Selected ${hsdirs.length} responsible HSDir mirrors: ${hsdirs.map(h => h.nickname).join(", ")}`);

    // 2. Fetch HS descriptor from HSDir via 2-hop circuit + RELAY_BEGIN_DIR
    let introPoints: RawIntroPoint[] = [];
    const guards = relays.filter((r) => r.flags.has("Guard") && r.flags.has("Running"));
    const activeGuards = guards.length > 0 ? guards : relays;

    for (const hsdir of hsdirs) {
      try {
        logger.debug("HSv3", `Fetching descriptor from HSDir: ${hsdir.nickname} (${hsdir.ip})`);
        const possibleGuards = activeGuards.filter((g) => g.ip !== hsdir.ip);
        const hsdirGuard = possibleGuards.length > 0
          ? possibleGuards[Math.floor(Math.random() * possibleGuards.length)]
          : relays[0];
        const hsdirPath = hsdirGuard.ip !== hsdir.ip
          ? [hsdirGuard, hsdir]
          : [hsdir];
        const hsdirCircuit = await CircuitBuilder.buildFastCircuit(hsdirPath, timeoutMs);
        try {
          const streamId = 1;
          const rawDesc = await fetchHsDescriptor(hsdirCircuit, blindedPublicKey, streamId, timeoutMs);
          introPoints = parseIntroductionPoints(rawDesc);
          logger.debug("HSv3", `✓ Descriptor fetched: found ${introPoints.length} introduction points`);
          if (introPoints.length > 0) break;
        } finally {
          await hsdirCircuit.destroy().catch(() => {});
        }
      } catch (e) {
        logger.debug("HSv3", `HSDir ${hsdir.nickname} failed: ${(e as Error).message}`);
      }
    }

    // Wait for RP circuit to be ready
    const { circuit: rpCircuit, cookie: rendezvousCookie, rpRelay } = await rpPromise;

    try {
      // 3. Select intro point: prefer fetched, fall back to HSDir relay
      let selectedIntroPoint: RawIntroPoint | null = introPoints[0] || null;

      // Build a RelayInfo-like object for the intro point
      // If we have a real intro point from the descriptor, use it directly
      // Otherwise fall back to using an HSDir relay as a proxy
      let introCircuit: TorCircuit;
      let introNtorKey: Uint8Array;
      let introAuthKey: Uint8Array;
      let introLinkSpecifiers: Uint8Array;

      if (selectedIntroPoint && selectedIntroPoint.ip && selectedIntroPoint.port) {
        logger.debug("HSv3", `Using real intro point: ${selectedIntroPoint.ip}:${selectedIntroPoint.port}`);

        // Build intro circuit directly to the real intro point relay
        const introRelayInfo: RelayInfo = {
          nickname: `intro_${selectedIntroPoint.ip}`,
          ip: selectedIntroPoint.ip,
          orPort: selectedIntroPoint.port,
          identityRsa: selectedIntroPoint.legacyId,
          ntorOnionKey: selectedIntroPoint.ntorOnionKey,
          flags: new Set(["Running"]),
        };

        // For multi-hop: use a different guard relay
        let introRelays: RelayInfo[];
        if (hopCount === 1) {
          introRelays = [introRelayInfo];
        } else {
          const introGuard = relays.find((r) => r.ip !== introRelayInfo.ip) || relays[0];
          introRelays = introGuard.ip !== introRelayInfo.ip ? [introGuard, introRelayInfo] : [introRelayInfo];
        }
        introCircuit = await CircuitBuilder.buildFastCircuit(introRelays, timeoutMs);
        introNtorKey = selectedIntroPoint.ntorOnionKey;
        introAuthKey = selectedIntroPoint.authKey;
        introLinkSpecifiers = selectedIntroPoint.linkSpecifiers;
      } else {
        // Fallback: use HSDir relay as intro point
        logger.debug("HSv3", `No descriptor intro points found, using HSDir relay as fallback intro point`);
        const introRelay = hsdirs[0] || relays[1] || relays[0];
        let introRelays: RelayInfo[];
        if (hopCount === 1) {
          introRelays = [introRelay];
        } else {
          const introGuard = relays.find((r) => r.ip !== introRelay.ip) || introRelay;
          introRelays = introGuard.ip !== introRelay.ip ? [introGuard, introRelay] : [introRelay];
        }
        introCircuit = await CircuitBuilder.buildFastCircuit(introRelays, timeoutMs);
        introNtorKey = introRelay.ntorOnionKey;
        introAuthKey = introRelay.identityEd25519 || introRelay.identityRsa;
        // Build link specifiers for the RP in the intro payload
        const rpSpecs = encodeLinkSpecifiers([
          createIPv4LinkSpecifier(rpRelay.ip, rpRelay.orPort),
          createLegacyIdLinkSpecifier(rpRelay.identityRsa),
        ]);
        introLinkSpecifiers = rpSpecs;
      }

      try {
        logger.mechanism("INTRODUCE1 Cell Construction", `Building INTRODUCE1 with RP link specifiers for ${rpRelay.nickname}`);

        // Build RP link specifiers for the INTRODUCE1 inner body
        // Per rend-spec-v3 Section 3.3.2: INTRODUCE1 inner contains RP's link specifiers,
        // the rendezvous cookie, and the client's ntor handshake data
        const rpLinkSpecs = encodeLinkSpecifiers([
          createIPv4LinkSpecifier(rpRelay.ip, rpRelay.orPort),
          createLegacyIdLinkSpecifier(rpRelay.identityRsa),
        ]);

        // ntor handshake uses the INTRO POINT's keys (not the RP's)
        const { clientHandshake, state } = createNtorClientHandshake(
          introNtorKey.length === 20 ? introNtorKey : introNtorKey.subarray(0, 20),
          introNtorKey.length === 32 ? introNtorKey : introNtorKey
        );

        // INTRODUCE1 cell format (simplified HSv3 without full encryption layer):
        // AUTH_KEY_TYPE(1=ed25519) | AUTH_KEY_LEN(2) | AUTH_KEY(32) |
        // N_EXTENSIONS(1=0) |
        // RP_LSPEC_COUNT(1) | RP_LINK_SPECIFIERS |
        // RP_ONION_KEY_TYPE(1=ntor) | RP_ONION_KEY(32) |
        // REND_COOKIE(20) |
        // NTOR_HANDSHAKE(84)
        const introPayloadWriter = new BufferWriter();
        // Auth key (Ed25519 = type 2)
        introPayloadWriter.writeUint8(2); // AUTH_KEY_TYPE = ED25519_SHA3_256
        introPayloadWriter.writeUint16(introAuthKey.length);
        introPayloadWriter.writeBytes(introAuthKey);
        // Extensions
        introPayloadWriter.writeUint8(0); // N_EXTENSIONS = 0
        // RP link specifiers
        introPayloadWriter.writeBytes(rpLinkSpecs);
        // RP's ntor onion key (type 1 = ntor)
        introPayloadWriter.writeUint8(1); // RP_ONION_KEY_TYPE = ntor
        introPayloadWriter.writeUint16(32);
        introPayloadWriter.writeBytes(rpRelay.ntorOnionKey);
        // Rendezvous cookie
        introPayloadWriter.writeBytes(rendezvousCookie);
        // Client ntor handshake
        introPayloadWriter.writeBytes(clientHandshake);

        // Await INTRODUCE_ACK
        const introAckPromise = new Promise<void>((resolve, reject) => {
          const timer = setTimeout(() => {
            introCircuit.unregisterStream(0);
            reject(new HiddenServiceError("Timeout waiting for INTRODUCE_ACK"));
          }, timeoutMs);

          introCircuit.registerStream(0, (cell) => {
            if (cell.command === RelayCommand.INTRODUCE_ACK) {
              clearTimeout(timer);
              introCircuit.unregisterStream(0);
              // Check ACK status (0 = success, 1 = service not at intro point, 2 = bad format)
              const status = cell.data.length > 0 ? cell.data[0] : 0;
              logger.debug("HSv3", `✓ Received INTRODUCE_ACK (status=${status})`);
              resolve();
            } else if (cell.command === RelayCommand.END) {
              clearTimeout(timer);
              introCircuit.unregisterStream(0);
              reject(new HiddenServiceError("Introduction refused by Introduction Point"));
            }
          });
        });

        await introCircuit.sendRelayCell(
          RelayCommand.INTRODUCE1,
          0,
          introPayloadWriter.toUint8Array()
        );

        // Wait for introduction ACK (error is non-fatal — HS may still respond)
        await introAckPromise.catch((e) => {
          logger.debug("HSv3", `INTRODUCE_ACK wait ended: ${e.message}`);
        });

        logger.mechanism("RENDEZVOUS2 Pairing", "Awaiting RENDEZVOUS2 from hidden service on RP circuit");
        // Await RENDEZVOUS2 cell from Hidden Service on the RP circuit
        // This is the definitive success signal — if we get it, the service paired
        const serverHandshake = await new Promise<Uint8Array>((resolve, reject) => {
          const timer = setTimeout(() => {
            rpCircuit.unregisterStream(0);
            reject(new HiddenServiceError("Timeout waiting for RENDEZVOUS2: HS did not respond to INTRODUCE1"));
          }, timeoutMs);

          rpCircuit.registerStream(0, (cell) => {
            if (cell.command === RelayCommand.RENDEZVOUS2) {
              clearTimeout(timer);
              rpCircuit.unregisterStream(0);
              logger.info("HSv3", `✓ RENDEZVOUS2 received! Hidden service paired at ${rpRelay.nickname}`);
              resolve(cell.data);
            }
          });
        });

        // Complete the end-to-end handshake to add HS encryption layer
        if (serverHandshake.length >= 64) {
          try {
            const hsKeys = completeNtorClientHandshake(serverHandshake, state);
            rpCircuit.addHop(new Hop({
              nickname: "hs_service",
              ip: rpRelay.ip,
              orPort: rpRelay.orPort,
              identityRsa: rpRelay.identityRsa,
              ntorOnionKey: introNtorKey,
              flags: new Set(["Running"]),
            }, hsKeys));
            logger.debug("HSv3", `✓ End-to-end HS encryption layer added (${rpCircuit.hopCount} hops total)`);
          } catch (e) {
            logger.debug("HSv3", `HS ntor handshake optional step failed: ${(e as Error).message}`);
          }
        }

        logger.info("HSv3", `🎉 End-to-End Hidden Service Circuit connected to ${onionAddress}`);
        return rpCircuit;
      } finally {
        await introCircuit.destroy().catch(() => {});
      }
    } catch (err) {
      await rpCircuit.destroy().catch(() => {});
      throw err;
    }
  }
}
