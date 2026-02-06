import { writeFileSync, mkdirSync, existsSync } from "fs";
import { join } from "path";
import { Finding } from "../findings/finding";
import { ReportingConfig } from "../core/config.loader";
import { JsonReporter } from "./json.reporter";
import { MarkdownReporter } from "./markdown.reporter";
import { CliSummary, CliSummaryOptions } from "./cli.summary";
import { logger } from "../core/logger";

export interface ReportOptions {
  targetUrl: string;
  scanDuration?: number;
  timestamp?: Date;
}

export interface GeneratedReport {
  format: string;
  path: string;
}

export class ReportGenerator {
  private config: ReportingConfig;
  private jsonReporter: JsonReporter;
  private markdownReporter: MarkdownReporter;

  constructor(config: ReportingConfig) {
    this.config = config;
    this.jsonReporter = new JsonReporter(config);
    this.markdownReporter = new MarkdownReporter(config);
  }

  async generate(findings: Finding[], options: ReportOptions): Promise<GeneratedReport[]> {
    const reports: GeneratedReport[] = [];
    const timestamp = options.timestamp || new Date();
    const dateStr = this.formatDate(timestamp);

    // Ensure output directory exists
    this.ensureOutputDir();

    for (const format of this.config.formats) {
      try {
        const report = this.generateReport(findings, format, options);
        const filename = this.getFilename(format, dateStr);
        const filepath = join(this.config.outputDir, filename);

        writeFileSync(filepath, report, "utf-8");

        reports.push({ format, path: filepath });
      } catch (err) {
        logger.error(`Failed to generate ${format} report: ${(err as Error).message}`);
      }
    }

    return reports;
  }

  generateReport(
    findings: Finding[],
    format: "markdown" | "json",
    options: ReportOptions
  ): string {
    switch (format) {
      case "json":
        return this.jsonReporter.generate(findings, {
          targetUrl: options.targetUrl,
          scanDuration: options.scanDuration,
          includeEvidence: this.config.includeEvidence,
        });

      case "markdown":
        return this.markdownReporter.generate(findings, {
          targetUrl: options.targetUrl,
          scanDuration: options.scanDuration,
        });

      default:
        throw new Error(`Unsupported report format: ${format}`);
    }
  }

  renderCliSummary(findings: Finding[], options?: CliSummaryOptions): void {
    const summary = new CliSummary(options);
    summary.render(findings);
  }

  private ensureOutputDir(): void {
    if (!existsSync(this.config.outputDir)) {
      mkdirSync(this.config.outputDir, { recursive: true });
      logger.debug(`Created output directory: ${this.config.outputDir}`);
    }
  }

  private getFilename(format: "markdown" | "json", dateStr: string): string {
    const extension = format === "markdown" ? "md" : "json";
    return `security-report-${dateStr}.${extension}`;
  }

  private formatDate(date: Date): string {
    return date.toISOString().split("T")[0];
  }
}
