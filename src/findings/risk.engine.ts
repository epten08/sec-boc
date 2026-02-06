import { Finding, Severity, SEVERITY_WEIGHTS } from "./finding";
import { RawFinding } from "./raw.finding";

export interface RiskFactors {
  severity: Severity;
  category: string;
  hasExploit: boolean;
  hasFix: boolean;
  isExposed: boolean;
  cvssScore?: number;
}

export interface RiskScore {
  exploitability: number;
  confidence: number;
  riskScore: number;
}

const CATEGORY_EXPLOITABILITY: Record<string, number> = {
  // Critical categories - easily exploitable
  "SQL Injection": 0.95,
  Injection: 0.9,
  "Command Injection": 0.95,
  "Remote Code Execution": 1.0,

  // High categories
  XSS: 0.8,
  "Cross-Site Scripting (XSS)": 0.8,
  "Broken Authentication": 0.85,
  "Broken Access Control": 0.8,
  "Hardcoded Secret": 0.75,

  // Medium categories
  CSRF: 0.6,
  "Security Misconfiguration": 0.5,
  "Sensitive Data Exposure": 0.6,
  "Information Disclosure": 0.5,

  // Lower categories
  "TLS/SSL Issue": 0.4,
  "Missing Security Header": 0.3,
  "Dependency Vulnerability": 0.5,
  "NPM Dependency Vulnerability": 0.5,
  "OS Package Vulnerability": 0.4,
  "Container Vulnerability": 0.45,
};

const SOURCE_CONFIDENCE: Record<string, number> = {
  "Trivy Static": 0.9,
  "Trivy Image": 0.9,
  "OWASP ZAP API": 0.85,
  "AI Security Tester": 0.6,
};

export class RiskEngine {
  calculateRisk(raw: RawFinding): RiskScore {
    const factors = this.extractFactors(raw);
    const exploitability = this.calculateExploitability(factors, raw);
    const confidence = this.calculateConfidence(raw);
    const riskScore = this.calculateCompositeScore(factors, exploitability, confidence);

    return { exploitability, confidence, riskScore };
  }

  private extractFactors(raw: RawFinding): RiskFactors {
    return {
      severity: this.mapSeverity(raw.severityHint),
      category: raw.category,
      hasExploit: this.hasKnownExploit(raw),
      hasFix: !!raw.fixedVersion,
      isExposed: this.isExternallyExposed(raw),
    };
  }

  private calculateExploitability(factors: RiskFactors, raw: RawFinding): number {
    let score = 0.5; // Base score

    // Category-based exploitability
    const categoryScore = CATEGORY_EXPLOITABILITY[factors.category];
    if (categoryScore !== undefined) {
      score = categoryScore;
    }

    // Adjust for severity
    score *= 0.7 + SEVERITY_WEIGHTS[factors.severity] * 0.075;

    // Known exploit increases exploitability
    if (factors.hasExploit) {
      score = Math.min(score * 1.2, 1.0);
    }

    // Available fix slightly decreases urgency perception
    if (factors.hasFix) {
      score *= 0.95;
    }

    // External exposure increases risk
    if (factors.isExposed) {
      score = Math.min(score * 1.1, 1.0);
    }

    // CVE presence increases credibility
    if (raw.cve) {
      score = Math.min(score * 1.05, 1.0);
    }

    return Math.round(score * 100) / 100;
  }

  private calculateConfidence(raw: RawFinding): number {
    let confidence = SOURCE_CONFIDENCE[raw.source] ?? 0.7;

    // Evidence increases confidence
    if (raw.evidence && raw.evidence.length > 50) {
      confidence = Math.min(confidence + 0.1, 1.0);
    }

    // CVE/CWE increases confidence
    if (raw.cve) {
      confidence = Math.min(confidence + 0.1, 1.0);
    }
    if (raw.cwe) {
      confidence = Math.min(confidence + 0.05, 1.0);
    }

    // Reference URL increases confidence
    if (raw.reference) {
      confidence = Math.min(confidence + 0.05, 1.0);
    }

    return Math.round(confidence * 100) / 100;
  }

  private calculateCompositeScore(
    factors: RiskFactors,
    exploitability: number,
    confidence: number
  ): number {
    // Weighted formula: severity * exploitability * confidence
    const severityWeight = SEVERITY_WEIGHTS[factors.severity] / 4; // Normalize to 0-1
    const composite = severityWeight * 0.4 + exploitability * 0.35 + confidence * 0.25;

    return Math.round(composite * 100) / 100;
  }

  private mapSeverity(hint?: string): Severity {
    const upper = hint?.toUpperCase();
    if (upper === "CRITICAL") return "CRITICAL";
    if (upper === "HIGH") return "HIGH";
    if (upper === "MEDIUM") return "MEDIUM";
    return "LOW";
  }

  private hasKnownExploit(raw: RawFinding): boolean {
    // Check for known exploit indicators
    if (raw.cve) {
      // Could integrate with exploit-db or similar
      // For now, assume critical CVEs have exploits
      return raw.severityHint === "CRITICAL";
    }
    return false;
  }

  private isExternallyExposed(raw: RawFinding): boolean {
    // Check if the vulnerability is in an externally exposed component
    if (raw.endpoint) {
      return true; // API endpoints are exposed
    }

    // Check for web-facing categories
    const exposedCategories = [
      "XSS",
      "SQL Injection",
      "CSRF",
      "Broken Authentication",
      "Broken Access Control",
    ];

    return exposedCategories.some((cat) =>
      raw.category.toLowerCase().includes(cat.toLowerCase())
    );
  }

  recalculateAfterDedup(finding: Finding, duplicateCount: number): Finding {
    // Increase confidence when multiple sources report the same issue
    const confidenceBoost = Math.min(duplicateCount * 0.05, 0.2);
    const newConfidence = Math.min(finding.confidence + confidenceBoost, 1.0);

    // Recalculate risk score
    const severityWeight = SEVERITY_WEIGHTS[finding.severity] / 4;
    const newRiskScore =
      severityWeight * 0.4 + finding.exploitability * 0.35 + newConfidence * 0.25;

    return {
      ...finding,
      confidence: Math.round(newConfidence * 100) / 100,
      riskScore: Math.round(newRiskScore * 100) / 100,
      duplicateCount,
    };
  }
}
