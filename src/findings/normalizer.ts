import { RawFinding } from "./raw.finding";
import { Finding, Severity } from "./finding";
import { v4 as uuid } from "uuid";

export function normalizeFindings(raw: RawFinding[]): Finding[] {
  return raw.map((r) => ({
    id: uuid(),
    title: r.description,
    category: r.category,
    severity: mapSeverity(r.severityHint),
    endpoint: r.endpoint,
    evidence: r.evidence ?? "No evidence provided",
    exploitability: 0.5,
    confidence: 0.7,
    sources: [r.source],
  }));
}

function mapSeverity(hint?: string): Severity {
  switch (hint) {
    case "CRITICAL":
      return "CRITICAL";
    case "HIGH":
      return "HIGH";
    case "MEDIUM":
      return "MEDIUM";
    default:
      return "LOW";
  }
}
