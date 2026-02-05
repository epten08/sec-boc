export interface RawFinding {
  source: string;
  category: string;
  description: string;
  endpoint?: string;
  severityHint?: string;
  evidence?: string;
}
