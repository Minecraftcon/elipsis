/**
 * Tor Circuit Pool Manager.
 * Maintains a pool of pre-built, active circuits for zero-latency stream creation.
 */
import { TorCircuit } from "./circuit.ts";
import { CircuitBuilder } from "./builder.ts";
import { PathSelector } from "../directory/path_selector.ts";
import { RelayInfo } from "../common/types.ts";
import { CircuitError } from "../common/errors.ts";
import { logger } from "../common/logger.ts";

/**
 * Manages background pre-warmed circuit pool and automatic circuit recycling.
 */
export class CircuitPool {
  private activeCircuits: TorCircuit[] = [];
  private building = false;
  private minCircuits: number;
  private maxCircuits: number;
  private hopCount: number;
  private getRelays: () => RelayInfo[];
  private maintenanceTimer: any = null;

  /**
   * Constructs a new CircuitPool.
   * @param getRelays Relay directory provider function
   * @param minCircuits Minimum target warm circuits (default: 8)
   * @param maxCircuits Maximum pool capacity (default: 20)
   * @param hopCount Number of hops for pre-warmed circuits (1 to 5, default: 1)
   */
  constructor(getRelays: () => RelayInfo[], minCircuits = 8, maxCircuits = 20, hopCount = 1) {
    this.getRelays = getRelays;
    this.minCircuits = minCircuits;
    this.maxCircuits = maxCircuits;
    this.hopCount = hopCount;

    // Start background maintenance loop
    this.startMaintenanceLoop();
  }

  /**
   * Dynamically update target hop count for new circuits.
   * @param hops Number of hops
   */
  setHopCount(hops: number): void {
    this.hopCount = Math.max(1, Math.min(hops, 5));
  }

  /**
   * Pre-warm circuits in parallel so the client is immediately ready for instant requests.
   * Builds all needed circuits concurrently for fast startup.
   */
  async prewarm(): Promise<void> {
    const needed = Math.max(0, this.minCircuits - this.activeCircuits.length);
    if (needed === 0) return;

    logger.debug("CIRCUIT", `Pre-warming ${needed} circuits in parallel...`);
    const tasks: Promise<TorCircuit | null>[] = [];
    for (let i = 0; i < needed; i++) {
      tasks.push(this.buildOneCircuit());
    }
    await Promise.allSettled(tasks);
    logger.debug("CIRCUIT", `Pool pre-warm complete: ${this.activeCircuits.length} circuits ready`);
  }

  private startMaintenanceLoop(): void {
    if (this.maintenanceTimer) return;
    // 2s interval (was 5s) to recover from drain faster
    this.maintenanceTimer = setInterval(() => {
      this.maintainPool().catch(() => {});
    }, 2000);
  }

  private async maintainPool(): Promise<void> {
    // Filter closed circuits
    this.activeCircuits = this.activeCircuits.filter((c) => !c.isClosed);
    const deficit = this.minCircuits - this.activeCircuits.length;
    if (deficit > 0 && !this.building) {
      // Build up to 4 circuits in parallel to recover pool faster
      await this.refillPool(Math.min(deficit, 4));
    }
  }

  private async buildOneCircuit(targetPort = 443, maxAttempts = 3): Promise<TorCircuit | null> {
    const relays = this.getRelays();
    if (relays.length === 0) return null;

    let lastError: Error | null = null;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        let circuit: TorCircuit;
        if (this.hopCount === 1) {
          const guard = relays[Math.floor(Math.random() * relays.length)];
          circuit = await CircuitBuilder.build1HopCircuit(guard, 10000);
        } else if (this.hopCount === 2) {
          const path = relays.length >= 2 ? [relays[0], relays[1]] : [relays[0]];
          circuit = await CircuitBuilder.buildFastCircuit(path, 12000);
        } else {
          const path = PathSelector.select3HopPath(relays, { targetPort });
          circuit = await CircuitBuilder.build3HopCircuit(path, 15000);
        }
        this.activeCircuits.push(circuit);
        return circuit;
      } catch (err: any) {
        lastError = err;
        logger.debug("CIRCUIT", `Circuit build attempt ${attempt}/${maxAttempts} failed: ${err.message}`);
        if (attempt < maxAttempts) {
          await new Promise((r) => setTimeout(r, 150 * attempt));
        }
      }
    }

    logger.warn("CIRCUIT", `All ${maxAttempts} circuit build attempts failed: ${lastError?.message}`);
    return null;
  }

  /**
   * Acquire an active circuit from the pool with 0ms build wait.
   * Circuits are NOT marked dirty on every use — they expire naturally after 10 minutes.
   * This prevents the pool from being permanently depleted under high concurrency.
   * @param targetPort Destination port (default: 443)
   * @returns Established Tor circuit
   */
  async getCircuit(targetPort = 443): Promise<TorCircuit> {
    // Clean up only truly closed circuits (not dirty-by-mark)
    this.activeCircuits = this.activeCircuits.filter((c) => !c.isClosed);

    // Return any live circuit (round-robin to spread load)
    while (this.activeCircuits.length > 0) {
      const circuit = this.activeCircuits.shift()!;
      if (!circuit.isClosed) {
        // Put it back at the end for fair round-robin reuse
        this.activeCircuits.push(circuit);
        // Trigger background refill if we're running low
        if (this.activeCircuits.length < this.minCircuits) {
          this.refillPool(this.minCircuits - this.activeCircuits.length).catch(() => {});
        }
        return circuit;
      }
    }

    // Pool is temporarily dry — build one urgently (with retry)
    logger.warn("CIRCUIT", "Pool dry — building emergency circuit");
    const circuit = await this.buildOneCircuit(targetPort, 3);
    if (circuit) {
      // Kick off background refill to restore pool
      this.refillPool(this.minCircuits).catch(() => {});
      return circuit;
    }

    throw new CircuitError("Failed to acquire or build an active Tor circuit after multiple attempts");
  }

  /**
   * Refill the pool in the background up to maxCircuits.
   * @param count How many circuits to build in parallel (default: 1)
   */
  async refillPool(count = 1): Promise<void> {
    if (this.building) return;
    const available = this.maxCircuits - this.activeCircuits.length;
    if (available <= 0) return;

    this.building = true;
    try {
      const toBuild = Math.min(count, available);
      const tasks: Promise<TorCircuit | null>[] = [];
      for (let i = 0; i < toBuild; i++) {
        tasks.push(this.buildOneCircuit());
      }
      await Promise.allSettled(tasks);
    } catch (_e) {
      // Ignored for background refill
    } finally {
      this.building = false;
    }
  }

  /**
   * Destroy all circuits in pool.
   */
  async closeAll(): Promise<void> {
    if (this.maintenanceTimer) {
      clearInterval(this.maintenanceTimer);
      this.maintenanceTimer = null;
    }
    const circuits = [...this.activeCircuits];
    this.activeCircuits = [];
    await Promise.allSettled(circuits.map((c) => c.destroy()));
  }
}
