import { ExecutionContext } from "../orchestrator/context";
import { RawFinding } from "../findings/raw.finding";

export type ScannerCategory =
  | "static"
  | "container"
  | "dynamic"
  | "ai";

export interface Scanner {
  name: string;
  category: ScannerCategory;

  run(ctx: ExecutionContext): Promise<RawFinding[]>;
}
