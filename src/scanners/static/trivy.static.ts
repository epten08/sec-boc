import { Scanner } from "../scanner";
import { ExecutionContext } from "../../orchestrator/context";
import { RawFinding } from "../../findings/raw.finding";
import { runProcess, checkCommand } from "../../core/process.runner";
import { ScannerError } from "../../core/errors";
import { logger } from "../../core/logger";

interface TrivyResult {
  SchemaVersion: number;
  Results?: TrivyTarget[];
}

interface TrivyTarget {
  Target: string;
  Class: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
}

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title?: string;
  Description?: string;
  PrimaryURL?: string;
  CweIDs?: string[];
}

export class TrivyStaticScanner implements Scanner {
  name = "Trivy Static";
  category = "static" as const;

  private useDocker = false;

  async run(_ctx: ExecutionContext): Promise<RawFinding[]> {
    logger.scanner(this.name, "start", "Scanning filesystem for vulnerabilities");

    // Check for native trivy first, then Docker
    const hasTrivy = await checkCommand("trivy");
    const hasDocker = await checkCommand("docker");

    if (!hasTrivy && !hasDocker) {
      logger.warn("Neither Trivy nor Docker available, skipping static scan");
      return [];
    }

    if (!hasTrivy && hasDocker) {
      // Check if trivy image is available
      const imageCheck = await runProcess("docker", ["images", "-q", "aquasec/trivy"], { timeout: 10000 });
      if (!imageCheck.stdout.trim()) {
        logger.warn("Trivy Docker image not found. Pull with: docker pull aquasec/trivy");
        return [];
      }
      this.useDocker = true;
      logger.info("Using Trivy via Docker");
    }

    try {
      let result;
      const cwd = process.cwd();

      if (this.useDocker) {
        // Run Trivy via Docker, mounting current directory
        result = await runProcess(
          "docker",
          [
            "run", "--rm",
            "-v", `${cwd}:/workspace`,
            "aquasec/trivy",
            "fs", "/workspace",
            "--format", "json",
            "--scanners", "vuln,secret,misconfig"
          ],
          { timeout: 300000 }
        );
      } else {
        result = await runProcess(
          "trivy",
          ["fs", ".", "--format", "json", "--scanners", "vuln,secret,misconfig"],
          { timeout: 300000 }
        );
      }

      if (result.exitCode !== 0 && !result.stdout) {
        throw new ScannerError(
          `Trivy scan failed: ${result.stderr}`,
          this.name
        );
      }

      const findings = this.parseResults(result.stdout);
      logger.scanner(this.name, "done", `Found ${findings.length} issues`);
      return findings;
    } catch (err) {
      if (err instanceof ScannerError) throw err;
      logger.scanner(this.name, "error", (err as Error).message);
      throw new ScannerError(
        `Static scan failed: ${(err as Error).message}`,
        this.name,
        err as Error
      );
    }
  }

  private parseResults(output: string): RawFinding[] {
    const findings: RawFinding[] = [];

    if (!output.trim()) {
      return findings;
    }

    let data: TrivyResult;
    try {
      data = JSON.parse(output);
    } catch {
      logger.warn("Failed to parse Trivy output");
      return findings;
    }

    for (const target of data.Results || []) {
      for (const vuln of target.Vulnerabilities || []) {
        findings.push({
          source: this.name,
          category: this.mapCategory(target.Class, target.Type),
          description: vuln.Title || vuln.Description || `${vuln.VulnerabilityID} in ${vuln.PkgName}`,
          severityHint: vuln.Severity,
          evidence: `${vuln.PkgName}@${vuln.InstalledVersion} in ${target.Target}`,
          cve: vuln.VulnerabilityID,
          cwe: vuln.CweIDs?.[0],
          package: vuln.PkgName,
          version: vuln.InstalledVersion,
          fixedVersion: vuln.FixedVersion,
          reference: vuln.PrimaryURL,
        });
      }
    }

    return findings;
  }

  private mapCategory(targetClass: string, targetType: string): string {
    if (targetClass === "secret") return "Hardcoded Secret";
    if (targetClass === "config") return "Misconfiguration";
    if (targetType === "npm" || targetType === "yarn") return "NPM Dependency Vulnerability";
    if (targetType === "pip" || targetType === "poetry") return "Python Dependency Vulnerability";
    if (targetType === "go") return "Go Dependency Vulnerability";
    return "Dependency Vulnerability";
  }
}
