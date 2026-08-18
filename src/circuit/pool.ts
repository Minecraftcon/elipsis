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
   * @param minCircuits Minimum target warm circuits (default: 2)
   * @param maxCircuits Maximum pool capacity (default: 5)
   * @param hopCount Number of hops for pre-warmed circuits (1 to 5, default: 1)
   */
  constructor(getRelays: () => RelayInfo[], minCircuits = 2, maxCircuits = 5, hopCount = 1) {
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
   */
  async prewarm(): Promise<void> {
    const tasks: Promise<TorCircuit | null>[] = [];
    const needed = Math.max(0, this.minCircuits - this.activeCircuits.length);
    for (let i = 0; i < needed; i++) {
      tasks.push(this.buildOneCircuit());
    }
    await Promise.allSettled(tasks);
  }

  private startMaintenanceLoop(): void {
    if (this.maintenanceTimer) return;
    this.maintenanceTimer = setInterval(() => {
      this.maintainPool().catch(() => {});
    }, 5000);
  }

  private async maintainPool(): Promise<void> {
    // Filter closed or dirty circuits
    this.activeCircuits = this.activeCircuits.filter((c) => !c.isClosed && !c.isDirty);
    if (this.activeCircuits.length < this.minCircuits && !this.building) {
      await this.refillPool();
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
          await new Promise((r) => setTimeout(r, 200 * attempt));
        }
      }
    }

    logger.warn("CIRCUIT", `All ${maxAttempts} circuit build attempts failed: ${lastError?.message}`);
    return null;
  }

  /**
   * Acquire an active circuit from the pool with 0ms build wait.
   * @param targetPort Destination port (default: 443)
   * @returns Established Tor circuit
   */
  async getCircuit(targetPort = 443): Promise<TorCircuit> {
    // Clean up closed or dirty circuits
    this.activeCircuits = this.activeCircuits.filter((c) => !c.isClosed && !c.isDirty);

    while (this.activeCircuits.length > 0) {
      const circuit = this.activeCircuits.shift()!;
      if (!circuit.isClosed) {
        this.activeCircuits.push(circuit);
        circuit.markDirty();
        // Background refill to keep pool warm
        this.refillPool().catch(() => {});
        return circuit;
      }
    }

    // If pool is temporarily dry, build one with retry
    const circuit = await this.buildOneCircuit(targetPort, 3);
    if (circuit) {
      circuit.markDirty();
      // Background refill
      this.refillPool().catch(() => {});
      return circuit;
    }

    throw new CircuitError("Failed to acquire or build an active Tor circuit after multiple attempts");
  }

  /**
   * Refill the pool in the background up to maxCircuits.
   */
  async refillPool(): Promise<void> {
    if (this.building || this.activeCircuits.length >= this.maxCircuits) {
      return;
    }

    this.building = true;
    try {
      await this.buildOneCircuit();
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

