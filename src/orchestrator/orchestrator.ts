import { Scanner, ScannerCategory } from "../scanners/scanner";
import { ExecutionContext } from "./context";
import { Finding } from "../findings/finding";
import { RawFinding } from "../findings/raw.finding";
import { normalizeFindings } from "../findings/normalizer";
import { logger } from "../core/logger";
import { ScannerError } from "../core/errors";

export interface OrchestratorOptions {
  enabledCategories?: ScannerCategory[];
  parallel?: boolean;
  continueOnError?: boolean;
}

export class Orchestrator {
  private scanners: Scanner[];
  private options: OrchestratorOptions;

  constructor(scanners: Scanner[], options: OrchestratorOptions = {}) {
    this.scanners = scanners;
    this.options = {
      enabledCategories: ["static", "container", "dynamic"],
      parallel: false,
      continueOnError: true,
      ...options,
    };
  }

  async run(ctx: ExecutionContext): Promise<Finding[]> {
    const enabledScanners = this.scanners.filter(
      (s) => this.options.enabledCategories?.includes(s.category)
    );

    if (enabledScanners.length === 0) {
      logger.warn("No scanners enabled");
      return [];
    }

    logger.info(`Running ${enabledScanners.length} scanners`);

    let rawFindings: RawFinding[];

    if (this.options.parallel) {
      rawFindings = await this.runParallel(enabledScanners, ctx);
    } else {
      rawFindings = await this.runSequential(enabledScanners, ctx);
    }

    const normalized = normalizeFindings(rawFindings);

    logger.info(`Scan complete: ${normalized.length} findings`);
    return normalized;
  }

  private async runSequential(scanners: Scanner[], ctx: ExecutionContext): Promise<RawFinding[]> {
    const rawFindings: RawFinding[] = [];

    for (const scanner of scanners) {
      try {
        const results = await scanner.run(ctx);
        rawFindings.push(...results);
      } catch (err) {
        if (err instanceof ScannerError) {
          logger.error(`Scanner ${scanner.name} failed: ${err.message}`);
        } else {
          logger.error(`Scanner ${scanner.name} failed: ${(err as Error).message}`);
        }

        if (!this.options.continueOnError) {
          throw err;
        }
      }
    }

    return rawFindings;
  }

  private async runParallel(scanners: Scanner[], ctx: ExecutionContext): Promise<RawFinding[]> {
    const results = await Promise.allSettled(
      scanners.map((scanner) => scanner.run(ctx))
    );

    const rawFindings: RawFinding[] = [];

    for (let i = 0; i < results.length; i++) {
      const result = results[i];
      const scanner = scanners[i];

      if (result.status === "fulfilled") {
        rawFindings.push(...result.value);
      } else {
        logger.error(`Scanner ${scanner.name} failed: ${result.reason}`);

        if (!this.options.continueOnError) {
          throw result.reason;
        }
      }
    }

    return rawFindings;
  }
}
