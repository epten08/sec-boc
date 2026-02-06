import { Command } from "commander";
import { ScanOptions, parseSeverity, parseFormats } from "../options";
import { loadConfig, validateConfig, SecurityBotConfig } from "../../core/config.loader";
import { logger } from "../../core/logger";
import { Finding } from "../../findings/finding";
import { AttackAnalyzer } from "../../findings/attack.analyzer";
import { Orchestrator } from "../../orchestrator/orchestrator";
import { EnvironmentManager } from "../../orchestrator/environment.manager";
import { ExecutionContext } from "../../orchestrator/context";
import { TrivyStaticScanner } from "../../scanners/static/trivy.static";
import { TrivyImageScanner } from "../../scanners/container/trivy.image";
import { ZapApiScanner } from "../../scanners/dynamic/zap.api";
import { AIScanner } from "../../scanners/ai/ai.scanner";
import { Scanner, ScannerCategory } from "../../scanners/scanner";
import { ReportGenerator } from "../../reports/report.generator";

export function createRunCommand(): Command {
  const cmd = new Command("scan")
    .description("Run security scans against the target")
    .option("-c, --config <path>", "Path to config file")
    .option("-t, --target <url>", "Target URL (overrides config)")
    .option("-o, --output <dir>", "Output directory for reports")
    .option(
      "-f, --format <formats>",
      "Output formats (comma-separated: markdown,json)",
      parseFormats,
      []
    )
    .option(
      "--fail-on <severity>",
      "Fail if findings at this severity or above (LOW, MEDIUM, HIGH, CRITICAL)",
      parseSeverity
    )
    .option("-v, --verbose", "Enable verbose output")
    .option("-q, --quiet", "Suppress non-essential output")
    .option("--skip-static", "Skip static analysis")
    .option("--skip-container", "Skip container scanning")
    .option("--skip-dynamic", "Skip dynamic API scanning")
    .option("--skip-ai", "Skip AI-assisted testing")
    .action(async (options: ScanOptions) => {
      await runScan(options);
    });

  return cmd;
}

async function runScan(options: ScanOptions): Promise<void> {
  // Configure logger based on options
  if (options.verbose) {
    logger.setLevel("debug");
  } else if (options.quiet) {
    logger.setLevel("warn");
  }

  logger.banner("Security Bot - Scan");

  // Load and validate config
  let config: SecurityBotConfig;
  try {
    config = loadConfig(options.config);

    // Apply CLI overrides
    if (options.target) {
      config.target.baseUrl = options.target;
      // Clear dockerCompose when explicit target is provided
      config.target.dockerCompose = undefined;
    }
    if (options.output) {
      config.reporting.outputDir = options.output;
    }
    if (options.format && options.format.length > 0) {
      config.reporting.formats = options.format as ("markdown" | "json")[];
    }
    if (options.failOn) {
      config.thresholds.failOn = options.failOn;
    }

    // Apply skip flags
    if (options.skipStatic) {
      config.scanners.static.enabled = false;
    }
    if (options.skipContainer) {
      config.scanners.container.enabled = false;
    }
    if (options.skipDynamic) {
      config.scanners.dynamic.enabled = false;
    }
    if (options.skipAi) {
      config.scanners.ai.enabled = false;
    }

    validateConfig(config);
  } catch (err) {
    logger.error(`Configuration error: ${(err as Error).message}`);
    process.exit(2);
  }

  logger.info("Configuration loaded", {
    target: config.target.baseUrl || config.target.dockerCompose,
    failOn: config.thresholds.failOn,
  });

  // Log enabled scanners
  const enabledScanners: string[] = [];
  if (config.scanners.static.enabled) enabledScanners.push("static");
  if (config.scanners.container.enabled) enabledScanners.push("container");
  if (config.scanners.dynamic.enabled) enabledScanners.push("dynamic");
  if (config.scanners.ai.enabled) enabledScanners.push("ai");

  logger.info(`Enabled scanners: ${enabledScanners.join(", ") || "none"}`);

  // Setup environment
  const envManager = new EnvironmentManager(config);
  let findings: Finding[] = [];
  const scanStartTime = Date.now();

  try {
    logger.banner("Environment Setup");
    const envInfo = await envManager.setup();

    // Build execution context
    const ctx: ExecutionContext = {
      targetUrl: envInfo.baseUrl,
      environment: envInfo,
      auth: config.auth ? {
        type: config.auth.type,
        token: config.auth.token,
        apiKey: config.auth.apiKey,
        headerName: config.auth.headerName,
      } : undefined,
      config: {
        failOnSeverity: config.thresholds.failOn,
      },
      endpoints: config.target.endpoints,
    };

    // Create scanners based on config
    const scanners = createScanners(config);
    const enabledCategories = getEnabledCategories(config);

    // Run orchestrator
    logger.banner("Running Scans");
    const orchestrator = new Orchestrator(scanners, {
      enabledCategories,
      continueOnError: true,
    });

    findings = await orchestrator.run(ctx);

    // Display CLI summary
    logger.banner("Results");
    const reportGenerator = new ReportGenerator(config.reporting);
    reportGenerator.renderCliSummary(findings, {
      verbose: options.verbose,
      showEvidence: config.reporting.includeEvidence,
    });

    // Generate reports
    if (config.reporting.formats.length > 0) {
      logger.banner("Generating Reports");
      const reports = await reportGenerator.generate(findings, {
        targetUrl: ctx.targetUrl,
        scanDuration: Date.now() - scanStartTime,
      });

      for (const report of reports) {
        logger.info(`Generated ${report.format} report: ${report.path}`);
      }
    }

  } catch (err) {
    logger.error(`Scan failed: ${(err as Error).message}`);
    process.exit(1);
  } finally {
    await envManager.teardown();
  }

  // Determine exit code based on attack feasibility analysis
  const attackAnalyzer = new AttackAnalyzer();
  const verdict = attackAnalyzer.generateVerdict(findings);

  if (verdict.verdict === "UNSAFE") {
    logger.error(`Deployment blocked: ${verdict.reason}`);
    if (verdict.confirmedExploits.length > 0) {
      logger.error(`${verdict.confirmedExploits.length} confirmed exploit(s) detected`);
    }
    process.exit(1);
  } else if (verdict.verdict === "REVIEW_REQUIRED") {
    logger.warn(`Review required: ${verdict.reason}`);
    process.exit(0); // Don't fail, but warn
  } else {
    logger.info("Security analysis complete - safe to deploy");
    process.exit(0);
  }
}

function createScanners(config: SecurityBotConfig): Scanner[] {
  const scanners: Scanner[] = [
    new TrivyStaticScanner(),
    new TrivyImageScanner(),
    new ZapApiScanner(),
  ];

  // Add AI scanner if configured
  if (config.scanners.ai.enabled && config.scanners.ai.provider) {
    scanners.push(
      new AIScanner({
        provider: config.scanners.ai.provider,
        model: config.scanners.ai.model || "llama3",
        baseUrl: config.scanners.ai.baseUrl,
        maxTests: config.scanners.ai.maxTests,
      })
    );
  }

  return scanners;
}

function getEnabledCategories(config: SecurityBotConfig): ScannerCategory[] {
  const categories: ScannerCategory[] = [];
  if (config.scanners.static.enabled) categories.push("static");
  if (config.scanners.container.enabled) categories.push("container");
  if (config.scanners.dynamic.enabled) categories.push("dynamic");
  if (config.scanners.ai.enabled) categories.push("ai");
  return categories;
}

