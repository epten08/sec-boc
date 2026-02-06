import { Finding } from "../findings/finding";
import { ReportingConfig } from "../core/config.loader";

export interface JsonReport {
  metadata: {
    generatedAt: string;
    version: string;
    targetUrl: string;
    scanDuration?: number;
  };
  summary: {
    total: number;
    bySeverity: Record<string, number>;
    byCategory: Record<string, number>;
    deduplicated: number;
  };
  findings: Finding[];
}

export interface JsonReporterOptions {
  targetUrl: string;
  scanDuration?: number;
  includeEvidence?: boolean;
}

export class JsonReporter {
  private config: ReportingConfig;

  constructor(config: ReportingConfig) {
    this.config = config;
  }

  generate(findings: Finding[], options: JsonReporterOptions): string {
    const report = this.buildReport(findings, options);
    return JSON.stringify(report, null, 2);
  }

  private buildReport(findings: Finding[], options: JsonReporterOptions): JsonReport {
    const bySeverity: Record<string, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };

    const byCategory: Record<string, number> = {};
    let deduplicated = 0;

    for (const finding of findings) {
      bySeverity[finding.severity]++;

      if (!byCategory[finding.category]) {
        byCategory[finding.category] = 0;
      }
      byCategory[finding.category]++;

      if (finding.deduplicated) {
        deduplicated++;
      }
    }

    // Optionally strip evidence for smaller reports
    const reportFindings = this.config.includeEvidence
      ? findings
      : findings.map((f) => ({ ...f, evidence: "[redacted]" }));

    return {
      metadata: {
        generatedAt: new Date().toISOString(),
        version: "1.0.0",
        targetUrl: options.targetUrl,
        scanDuration: options.scanDuration,
      },
      summary: {
        total: findings.length,
        bySeverity,
        byCategory,
        deduplicated,
      },
      findings: reportFindings,
    };
  }
}
