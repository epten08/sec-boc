/**
 * Integration tests for Security Bot
 *
 * These tests validate the end-to-end pipeline without requiring
 * external tools (Trivy, ZAP, Ollama) to be installed.
 */

import { loadConfig, validateConfig } from "../src/core/config.loader";
import { logger } from "../src/core/logger";
import { Finding, Severity } from "../src/findings/finding";
import { normalizeFindings, sortByRisk } from "../src/findings/normalizer";
import { RawFinding } from "../src/findings/raw.finding";
import { ReportGenerator } from "../src/reports/report.generator";
import { JsonReporter } from "../src/reports/json.reporter";
import { MarkdownReporter } from "../src/reports/markdown.reporter";
import { CliSummary } from "../src/reports/cli.summary";
import { existsSync, rmSync, mkdirSync } from "fs";
import { join } from "path";

// Test utilities
function assert(condition: boolean, message: string): void {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

function assertEqual<T>(actual: T, expected: T, message: string): void {
  if (actual !== expected) {
    throw new Error(`${message}: expected ${expected}, got ${actual}`);
  }
}

async function runTest(name: string, fn: () => Promise<void> | void): Promise<boolean> {
  try {
    await fn();
    console.log(`  ✓ ${name}`);
    return true;
  } catch (err) {
    console.log(`  ✗ ${name}`);
    console.log(`    Error: ${(err as Error).message}`);
    return false;
  }
}

// Test Data
function createMockRawFindings(): RawFinding[] {
  return [
    {
      description: "SQL Injection in login endpoint - The login endpoint is vulnerable to SQL injection",
      severityHint: "CRITICAL",
      category: "Injection",
      source: "zap",
      endpoint: "/api/login",
      evidence: "Parameter 'username' appears to be vulnerable to SQL injection",
      cve: "CVE-2023-1234",
      cwe: "CWE-89",
    },
    {
      description: "Cross-Site Scripting (XSS) - Reflected XSS in search endpoint",
      severityHint: "HIGH",
      category: "XSS",
      source: "zap",
      endpoint: "/api/search",
      evidence: "<script>alert(1)</script> reflected in response",
    },
    {
      description: "Vulnerable dependency: lodash < 4.17.21 has prototype pollution",
      severityHint: "HIGH",
      category: "Dependency Vulnerability",
      source: "trivy",
      package: "lodash",
      version: "4.17.20",
      fixedVersion: "4.17.21",
      cve: "CVE-2021-23337",
    },
    {
      description: "Missing security headers - Response missing X-Content-Type-Options header",
      severityHint: "LOW",
      category: "Misconfiguration",
      source: "zap",
      endpoint: "/api/users",
    },
    {
      description: "SQL Injection in login endpoint - SQL injection detected via AI testing",
      severityHint: "CRITICAL",
      category: "Injection",
      source: "ai",
      endpoint: "/api/login",
      evidence: "UNION SELECT attack successful",
      cve: "CVE-2023-1234",
    },
  ];
}

// Tests
async function testConfigLoader(): Promise<boolean> {
  console.log("\n📋 Config Loader Tests:");
  let passed = 0;
  let total = 0;

  total++;
  if (await runTest("loads default config when no file specified", () => {
    const config = loadConfig();
    assert(config !== null, "Config should not be null");
    assert(config.target !== undefined, "Target should be defined");
  })) passed++;

  total++;
  if (await runTest("validates config structure", () => {
    const config = loadConfig();
    validateConfig(config);
    assert(config.scanners !== undefined, "Scanners should be defined");
  })) passed++;

  total++;
  if (await runTest("throws on missing explicit config file", () => {
    let threw = false;
    try {
      loadConfig("nonexistent.yml");
    } catch (err) {
      threw = true;
      assert((err as Error).message.includes("Config file not found"), "Should throw ConfigError");
    }
    assert(threw, "Should throw when explicit config file is missing");
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testFindingsNormalizer(): Promise<boolean> {
  console.log("\n🔍 Findings Normalizer Tests:");
  let passed = 0;
  let total = 0;

  const rawFindings = createMockRawFindings();

  total++;
  if (await runTest("normalizes raw findings to Finding objects", () => {
    const normalized = normalizeFindings(rawFindings);
    assert(Array.isArray(normalized), "Should return array");
    assert(normalized.length > 0, "Should have findings");
    assert(normalized[0].riskScore !== undefined, "Should have risk score");
  })) passed++;

  total++;
  if (await runTest("calculates risk scores", () => {
    const normalized = normalizeFindings(rawFindings);
    for (const finding of normalized) {
      assert(finding.riskScore >= 0 && finding.riskScore <= 1, "Risk score should be 0-1");
      assert(finding.exploitability >= 0, "Exploitability should be >= 0");
      assert(finding.confidence >= 0, "Confidence should be >= 0");
    }
  })) passed++;

  total++;
  if (await runTest("deduplicates similar findings", () => {
    const normalized = normalizeFindings(rawFindings);
    // Should deduplicate the two SQL injection findings
    const sqlFindings = normalized.filter(f => f.title.includes("SQL Injection"));
    assert(sqlFindings.length === 1, "Should deduplicate SQL injection findings");
    assert(sqlFindings[0].duplicateCount >= 1, "Should track duplicate count");
  })) passed++;

  total++;
  if (await runTest("sorts by risk correctly", () => {
    const normalized = normalizeFindings(rawFindings);
    const sorted = sortByRisk(normalized);
    for (let i = 1; i < sorted.length; i++) {
      assert(sorted[i - 1].riskScore >= sorted[i].riskScore, "Should be sorted by risk desc");
    }
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testReporting(): Promise<boolean> {
  console.log("\n📊 Reporting Tests:");
  let passed = 0;
  let total = 0;

  const rawFindings = createMockRawFindings();
  const findings = normalizeFindings(rawFindings);

  const reportConfig = {
    formats: ["json", "markdown"] as ("json" | "markdown")[],
    outputDir: "./test-reports",
    includeEvidence: true,
  };

  total++;
  if (await runTest("generates JSON report", () => {
    const reporter = new JsonReporter(reportConfig);
    const json = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    const parsed = JSON.parse(json);
    assert(parsed.metadata !== undefined, "Should have metadata");
    assert(parsed.summary !== undefined, "Should have summary");
    assert(parsed.findings !== undefined, "Should have findings");
    assert(parsed.summary.total === findings.length, "Should have correct count");
  })) passed++;

  total++;
  if (await runTest("generates Markdown report", () => {
    const reporter = new MarkdownReporter(reportConfig);
    const md = reporter.generate(findings, { targetUrl: "http://localhost:3000" });
    assert(md.includes("# Security Scan Report"), "Should have title");
    assert(md.includes("## Executive Summary"), "Should have summary");
    assert(md.includes("## Findings Summary"), "Should have findings table");
  })) passed++;

  total++;
  if (await runTest("CLI summary renders without error", () => {
    const summary = new CliSummary({ maxFindings: 5, verbose: false });
    // Just ensure it doesn't throw
    summary.render(findings);
  })) passed++;

  total++;
  if (await runTest("ReportGenerator creates files", async () => {
    const testDir = "./test-output";
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
    mkdirSync(testDir, { recursive: true });

    const generator = new ReportGenerator({
      ...reportConfig,
      outputDir: testDir,
    });

    const reports = await generator.generate(findings, {
      targetUrl: "http://localhost:3000",
      scanDuration: 5000,
    });

    assert(reports.length === 2, "Should generate 2 reports");
    for (const report of reports) {
      assert(existsSync(report.path), `Report should exist: ${report.path}`);
    }

    // Cleanup
    rmSync(testDir, { recursive: true });
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

async function testSeverityWeights(): Promise<boolean> {
  console.log("\n⚖️ Severity Weight Tests:");
  let passed = 0;
  let total = 0;

  const rawFindings = createMockRawFindings();
  const findings = normalizeFindings(rawFindings);

  total++;
  if (await runTest("CRITICAL findings have highest risk", () => {
    const critical = findings.filter(f => f.severity === "CRITICAL");
    const others = findings.filter(f => f.severity !== "CRITICAL");

    if (critical.length > 0 && others.length > 0) {
      const avgCritical = critical.reduce((sum, f) => sum + f.riskScore, 0) / critical.length;
      const avgOthers = others.reduce((sum, f) => sum + f.riskScore, 0) / others.length;
      assert(avgCritical > avgOthers, "Critical should have higher avg risk");
    }
  })) passed++;

  total++;
  if (await runTest("exploitability affects risk score", () => {
    // Injection vulnerabilities should have higher exploitability
    const injections = findings.filter(f => f.category.toLowerCase().includes("injection"));
    for (const finding of injections) {
      assert(finding.exploitability > 0.5, "Injection should have high exploitability");
    }
  })) passed++;

  console.log(`  ${passed}/${total} tests passed`);
  return passed === total;
}

// Main test runner
async function main(): Promise<void> {
  console.log("═".repeat(60));
  console.log("          Security Bot Integration Tests");
  console.log("═".repeat(60));

  logger.setLevel("error"); // Suppress logs during tests

  const results: boolean[] = [];

  results.push(await testConfigLoader());
  results.push(await testFindingsNormalizer());
  results.push(await testReporting());
  results.push(await testSeverityWeights());

  console.log("\n" + "═".repeat(60));

  const allPassed = results.every(r => r);
  const passedCount = results.filter(r => r).length;

  if (allPassed) {
    console.log(`✓ All test suites passed (${passedCount}/${results.length})`);
    process.exit(0);
  } else {
    console.log(`✗ Some test suites failed (${passedCount}/${results.length} passed)`);
    process.exit(1);
  }
}

main().catch((err) => {
  console.error("Test runner failed:", err);
  process.exit(1);
});
