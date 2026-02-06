import chalk from "chalk";
import { Finding, Severity, SEVERITY_WEIGHTS } from "../findings/finding";
import { sortByRisk } from "../findings/normalizer";

export interface CliSummaryOptions {
  maxFindings?: number;
  showEvidence?: boolean;
  verbose?: boolean;
}

export class CliSummary {
  private options: Required<CliSummaryOptions>;

  constructor(options: CliSummaryOptions = {}) {
    this.options = {
      maxFindings: 10,
      showEvidence: false,
      verbose: false,
      ...options,
    };
  }

  render(findings: Finding[]): void {
    console.log();
    this.renderHeader(findings);
    this.renderSeverityBreakdown(findings);

    if (findings.length > 0) {
      this.renderTopFindings(findings);

      if (this.options.verbose) {
        this.renderCategoryBreakdown(findings);
        this.renderSourceBreakdown(findings);
      }
    }

    this.renderConclusion(findings);
    console.log();
  }

  private renderHeader(findings: Finding[]): void {
    const total = findings.length;
    const critical = findings.filter((f) => f.severity === "CRITICAL").length;
    const high = findings.filter((f) => f.severity === "HIGH").length;

    console.log(chalk.bold("═".repeat(60)));
    console.log(chalk.bold.white("                    SCAN RESULTS"));
    console.log(chalk.bold("═".repeat(60)));
    console.log();

    if (total === 0) {
      console.log(chalk.green.bold("  ✓ No vulnerabilities found!"));
    } else {
      console.log(chalk.white(`  Total Findings: ${chalk.bold(total)}`));

      if (critical > 0) {
        console.log(chalk.red.bold(`  ⚠ ${critical} CRITICAL vulnerabilities require immediate attention`));
      }
      if (high > 0) {
        console.log(chalk.yellow(`  ⚠ ${high} HIGH severity issues should be addressed promptly`));
      }
    }

    console.log();
  }

  private renderSeverityBreakdown(findings: Finding[]): void {
    const counts: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
    };

    for (const finding of findings) {
      counts[finding.severity]++;
    }

    console.log(chalk.bold("  Severity Breakdown:"));
    console.log();

    const maxCount = Math.max(...Object.values(counts), 1);
    const barWidth = 30;

    for (const severity of ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as Severity[]) {
      const count = counts[severity];
      const bar = this.renderBar(count, maxCount, barWidth);
      const color = this.getSeverityColor(severity);
      const label = severity.padEnd(8);

      console.log(`  ${color(label)} ${bar} ${count}`);
    }

    console.log();
  }

  private renderBar(value: number, max: number, width: number): string {
    if (max === 0) return chalk.gray("░".repeat(width));

    const filled = Math.round((value / max) * width);
    const empty = width - filled;

    return chalk.green("█".repeat(filled)) + chalk.gray("░".repeat(empty));
  }

  private renderTopFindings(findings: Finding[]): void {
    const sorted = sortByRisk(findings);
    const top = sorted.slice(0, this.options.maxFindings);

    console.log(chalk.bold("  Top Findings:"));
    console.log();

    for (let i = 0; i < top.length; i++) {
      const finding = top[i];
      const severity = this.getSeverityBadge(finding.severity);
      const title = this.truncate(finding.title, 50);

      console.log(`  ${chalk.gray(`${i + 1}.`)} ${severity} ${title}`);

      if (this.options.verbose) {
        console.log(chalk.gray(`     Category: ${finding.category}`));
        console.log(chalk.gray(`     Risk: ${finding.riskScore.toFixed(2)} | Sources: ${finding.sources.join(", ")}`));

        if (finding.cve) {
          console.log(chalk.gray(`     CVE: ${finding.cve}`));
        }

        if (this.options.showEvidence && finding.evidence) {
          const evidence = this.truncate(finding.evidence, 80);
          console.log(chalk.gray(`     Evidence: ${evidence}`));
        }

        console.log();
      }
    }

    if (findings.length > this.options.maxFindings) {
      console.log(chalk.gray(`  ... and ${findings.length - this.options.maxFindings} more findings`));
    }

    console.log();
  }

  private renderCategoryBreakdown(findings: Finding[]): void {
    const byCategory: Record<string, number> = {};

    for (const finding of findings) {
      byCategory[finding.category] = (byCategory[finding.category] || 0) + 1;
    }

    const sorted = Object.entries(byCategory)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    console.log(chalk.bold("  Top Categories:"));
    console.log();

    for (const [category, count] of sorted) {
      console.log(`  ${chalk.gray("•")} ${category}: ${count}`);
    }

    console.log();
  }

  private renderSourceBreakdown(findings: Finding[]): void {
    const bySource: Record<string, number> = {};

    for (const finding of findings) {
      for (const source of finding.sources) {
        bySource[source] = (bySource[source] || 0) + 1;
      }
    }

    console.log(chalk.bold("  Findings by Source:"));
    console.log();

    for (const [source, count] of Object.entries(bySource)) {
      console.log(`  ${chalk.gray("•")} ${source}: ${count}`);
    }

    console.log();
  }

  private renderConclusion(findings: Finding[]): void {
    console.log(chalk.bold("─".repeat(60)));

    if (findings.length === 0) {
      console.log(chalk.green("  Status: PASSED - No vulnerabilities detected"));
    } else {
      const critical = findings.filter((f) => f.severity === "CRITICAL").length;
      const high = findings.filter((f) => f.severity === "HIGH").length;

      if (critical > 0) {
        console.log(chalk.red.bold("  Status: FAILED - Critical vulnerabilities found"));
        console.log(chalk.red("  Action: Immediate remediation required"));
      } else if (high > 0) {
        console.log(chalk.yellow("  Status: WARNING - High severity issues found"));
        console.log(chalk.yellow("  Action: Address high severity findings promptly"));
      } else {
        console.log(chalk.blue("  Status: REVIEW - Non-critical findings detected"));
        console.log(chalk.blue("  Action: Review and address findings as appropriate"));
      }
    }

    console.log(chalk.bold("─".repeat(60)));
  }

  private getSeverityColor(severity: Severity): (text: string) => string {
    switch (severity) {
      case "CRITICAL":
        return chalk.red.bold;
      case "HIGH":
        return chalk.yellow;
      case "MEDIUM":
        return chalk.blue;
      case "LOW":
        return chalk.gray;
    }
  }

  private getSeverityBadge(severity: Severity): string {
    switch (severity) {
      case "CRITICAL":
        return chalk.bgRed.white.bold(" CRIT ");
      case "HIGH":
        return chalk.bgYellow.black(" HIGH ");
      case "MEDIUM":
        return chalk.bgBlue.white(" MED  ");
      case "LOW":
        return chalk.bgGray.white(" LOW  ");
    }
  }

  private truncate(text: string, maxLength: number): string {
    if (text.length <= maxLength) return text;
    return text.substring(0, maxLength - 3) + "...";
  }
}
