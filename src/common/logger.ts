/**
 * Elipsis Structured & Aggressive Debug Logging Subsystem.
 * Provides granular tracing across Link, Cell, Ntor Crypto, HSv3, Circuit, Stream, and Proxy layers.
 */

/**
 * Log severity levels for filtering output.
 */
export enum LogLevel {
  /** Granular wire-level and cryptographic trace logs */
  TRACE = 0,
  /** Debug logs including circuit events and handshakes */
  DEBUG = 1,
  /** Informational high-level operational status */
  INFO = 2,
  /** Warnings about transient failures or retries */
  WARN = 3,
  /** Unrecoverable errors */
  ERROR = 4,
  /** Mute all logging output */
  NONE = 5,
}

/**
 * Functional subsystem categories for structured logging.
 */
export type LogCategory =
  | "CORE"
  | "LINK"
  | "CELL"
  | "CIRCUIT"
  | "CRYPTO"
  | "NTOR"
  | "HSv3"
  | "HSDIR"
  | "STREAM"
  | "PROXY"
  | "FLOW"
  | "DIRECTORY"
  | "CLIENT"
  | "MECHANISM";

/**
 * Structured log event representation.
 */
export interface LogEntry {
  /** Timestamp when log event occurred */
  timestamp: Date;
  /** Log severity level */
  level: LogLevel;
  /** Subsystem category */
  category: LogCategory;
  /** Human-readable log message */
  message: string;
  /** Optional metadata payload */
  meta?: Record<string, unknown>;
  /** Optional associated error object */
  error?: Error;
}

/**
 * Custom log subscriber handler function.
 */
export type LogHandler = (entry: LogEntry) => void;

/**
 * Core logging service providing colorized console output and observer hooks.
 */
export class LoggerService {
  private level: LogLevel = LogLevel.INFO;
  private customHandlers: LogHandler[] = [];
  private colorEnabled = true;

  /**
   * Initializes logger and auto-detects DEBUG environment flags.
   */
  constructor() {
    // Enable debug automatically if ELIPSIS_DEBUG or DEBUG env is set
    try {
      if (typeof Deno !== "undefined" && Deno.env) {
        const envDebug = Deno.env.get("ELIPSIS_DEBUG") || Deno.env.get("DEBUG");
        if (envDebug === "1" || envDebug === "true" || envDebug === "*") {
          this.level = LogLevel.DEBUG;
        } else if (envDebug === "trace" || envDebug === "all") {
          this.level = LogLevel.TRACE;
        }
      }
    } catch (_e) {
      // Ignored if permissions are restricted
    }
  }

  /**
   * Set active minimum log severity level.
   */
  setLevel(level: LogLevel): void {
    this.level = level;
  }

  /**
   * Get active minimum log severity level.
   */
  getLevel(): LogLevel {
    return this.level;
  }

  /**
   * Quick toggle to enable debug or trace logging.
   */
  enableDebug(verbose = false): void {
    this.level = verbose ? LogLevel.TRACE : LogLevel.DEBUG;
  }

  /**
   * Disable all logging output.
   */
  disable(): void {
    this.level = LogLevel.NONE;
  }

  /**
   * Register a custom observer handler to receive structured log entries.
   */
  addHandler(handler: LogHandler): void {
    this.customHandlers.push(handler);
  }

  /**
   * Log fine-grained trace message.
   */
  trace(category: LogCategory, message: string, meta?: Record<string, unknown>): void {
    this.log(LogLevel.TRACE, category, message, meta);
  }

  /**
   * Log debug message.
   */
  debug(category: LogCategory, message: string, meta?: Record<string, unknown>): void {
    this.log(LogLevel.DEBUG, category, message, meta);
  }

  /**
   * Log informational message.
   */
  info(category: LogCategory, message: string, meta?: Record<string, unknown>): void {
    this.log(LogLevel.INFO, category, message, meta);
  }

  /**
   * Log warning message.
   */
  warn(category: LogCategory, message: string, meta?: Record<string, unknown>): void {
    this.log(LogLevel.WARN, category, message, meta);
  }

  /**
   * Log error message with optional Error instance.
   */
  error(category: LogCategory, message: string, error?: unknown, meta?: Record<string, unknown>): void {
    const errObj = error instanceof Error ? error : error ? new Error(String(error)) : undefined;
    this.log(LogLevel.ERROR, category, message, meta, errObj);
  }

  /**
   * Explain a specific protocol or cryptographic mechanism being executed.
   */
  mechanism(name: string, description: string, details?: Record<string, unknown>): void {
    if (this.level > LogLevel.DEBUG) return;
    const formatted = `⚙️  [MECHANISM: ${name}] ${description}`;
    this.log(LogLevel.DEBUG, "MECHANISM", formatted, details);
  }

  /**
   * Internal dispatcher for formatting and broadcasting log entries.
   * @internal
   */
  private log(
    level: LogLevel,
    category: LogCategory,
    message: string,
    meta?: Record<string, unknown>,
    error?: Error
  ): void {
    if (level < this.level) return;

    const entry: LogEntry = {
      timestamp: new Date(),
      level,
      category,
      message,
      meta,
      error,
    };

    // Dispatch to custom handlers
    for (const h of this.customHandlers) {
      try {
        h(entry);
      } catch (_e) {}
    }

    // Default console output
    this.printConsole(entry);
  }

  /**
   * Internal terminal ANSI color formatter.
   * @internal
   */
  private printConsole(entry: LogEntry): void {
    const timeStr = entry.timestamp.toISOString().split("T")[1].replace("Z", "");
    const levelStr = LogLevel[entry.level].padEnd(5);
    const catStr = `[${entry.category}]`.padEnd(11);

    const colors = {
      reset: "\x1b[0m",
      dim: "\x1b[2m",
      red: "\x1b[31m",
      green: "\x1b[32m",
      yellow: "\x1b[33m",
      blue: "\x1b[34m",
      magenta: "\x1b[35m",
      cyan: "\x1b[36m",
      brightYellow: "\x1b[93m",
      brightCyan: "\x1b[96m",
    };

    let catColor = colors.cyan;
    if (entry.category === "CRYPTO" || entry.category === "NTOR") catColor = colors.magenta;
    else if (entry.category === "HSv3") catColor = colors.brightCyan;
    else if (entry.category === "STREAM" || entry.category === "PROXY") catColor = colors.green;
    else if (entry.category === "FLOW") catColor = colors.yellow;
    else if (entry.category === "MECHANISM") catColor = colors.brightYellow;

    let lvlColor = colors.dim;
    if (entry.level === LogLevel.DEBUG) lvlColor = colors.blue;
    else if (entry.level === LogLevel.WARN) lvlColor = colors.yellow;
    else if (entry.level === LogLevel.ERROR) lvlColor = colors.red;

    const metaStr = entry.meta && Object.keys(entry.meta).length > 0
      ? ` ${colors.dim}${JSON.stringify(entry.meta)}${colors.reset}`
      : "";

    const errStr = entry.error
      ? `\n${colors.red}${entry.error.stack || entry.error.message}${colors.reset}`
      : "";

    console.log(
      `${colors.dim}${timeStr}${colors.reset} ${lvlColor}${levelStr}${colors.reset} ${catColor}${catStr}${colors.reset} ${entry.message}${metaStr}${errStr}`
    );
  }
}

/**
 * Global default logger singleton instance.
 */
export const logger: LoggerService = new LoggerService();
