export type Severity =
  | "LOW"
  | "MEDIUM"
  | "HIGH"
  | "CRITICAL";

export interface Finding {
  id: string;
  title: string;
  category: string;
  severity: Severity;

  endpoint?: string;
  evidence: string;

  exploitability: number; // 0.0 – 1.0
  confidence: number;     // 0.0 – 1.0

  sources: string[];
}
