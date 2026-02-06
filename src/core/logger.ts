import chalk from "chalk";

export type LogLevel = "debug" | "info" | "warn" | "error";

interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  context?: Record<string, unknown>;
}

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

const LEVEL_COLORS: Record<LogLevel, (text: string) => string> = {
  debug: chalk.gray,
  info: chalk.blue,
  warn: chalk.yellow,
  error: chalk.red,
};

const LEVEL_LABELS: Record<LogLevel, string> = {
  debug: "DBG",
  info: "INF",
  warn: "WRN",
  error: "ERR",
};

class Logger {
  private minLevel: LogLevel = "info";
  private jsonOutput = false;

  setLevel(level: LogLevel): void {
    this.minLevel = level;
  }

  setJsonOutput(enabled: boolean): void {
    this.jsonOutput = enabled;
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVELS[level] >= LOG_LEVELS[this.minLevel];
  }

  private formatTimestamp(): string {
    return new Date().toISOString();
  }

  private log(level: LogLevel, message: string, context?: Record<string, unknown>): void {
    if (!this.shouldLog(level)) return;

    const entry: LogEntry = {
      level,
      message,
      timestamp: this.formatTimestamp(),
      context,
    };

    if (this.jsonOutput) {
      console.log(JSON.stringify(entry));
      return;
    }

    const color = LEVEL_COLORS[level];
    const label = LEVEL_LABELS[level];
    const prefix = color(`[${label}]`);
    const time = chalk.dim(entry.timestamp.split("T")[1].slice(0, 8));

    let output = `${time} ${prefix} ${message}`;
    if (context && Object.keys(context).length > 0) {
      output += chalk.dim(` ${JSON.stringify(context)}`);
    }

    console.log(output);
  }

  debug(message: string, context?: Record<string, unknown>): void {
    this.log("debug", message, context);
  }

  info(message: string, context?: Record<string, unknown>): void {
    this.log("info", message, context);
  }

  warn(message: string, context?: Record<string, unknown>): void {
    this.log("warn", message, context);
  }

  error(message: string, context?: Record<string, unknown>): void {
    this.log("error", message, context);
  }

  scanner(name: string, status: "start" | "done" | "error", details?: string): void {
    const icon = status === "start" ? "→" : status === "done" ? "✓" : "✗";
    const color = status === "start" ? chalk.blue : status === "done" ? chalk.green : chalk.red;
    const msg = details ? `${name}: ${details}` : name;
    console.log(`  ${color(icon)} ${msg}`);
  }

  finding(severity: string, title: string): void {
    const colors: Record<string, (t: string) => string> = {
      CRITICAL: chalk.bgRed.white,
      HIGH: chalk.red,
      MEDIUM: chalk.yellow,
      LOW: chalk.gray,
    };
    const color = colors[severity] || chalk.white;
    console.log(`    ${color(`[${severity}]`)} ${title}`);
  }

  divider(): void {
    console.log(chalk.dim("─".repeat(60)));
  }

  banner(text: string): void {
    console.log();
    console.log(chalk.bold.cyan(`◆ ${text}`));
    this.divider();
  }
}

export const logger = new Logger();
