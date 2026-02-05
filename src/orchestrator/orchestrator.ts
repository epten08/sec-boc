import { Scanner } from "../scanners/scanner";
import { ExecutionContext } from "./context";
import { Finding } from "../findings/finding";
import { normalizeFindings } from "../findings/normalizer";

export class Orchestrator {
  private scanners: Scanner[];

  constructor(scanners: Scanner[]) {
    this.scanners = scanners;
  }

  async run(ctx: ExecutionContext): Promise<Finding[]> {
    const rawFindings = [];

    for (const scanner of this.scanners) {
      console.log(`[+] Running ${scanner.name} (${scanner.category})`);
      const results = await scanner.run(ctx);
      rawFindings.push(...results);
    }

    const normalized = normalizeFindings(rawFindings);

    return normalized;
  }
}
