import { Scanner } from "../scanner";
import { ExecutionContext } from "../../orchestrator/context";
import { RawFinding } from "../../findings/raw.finding";

export class TrivyImageScanner implements Scanner {
  name = "Trivy Image";
  category = "container" as const;

  async run(_: ExecutionContext): Promise<RawFinding[]> {
    return [
      {
        source: this.name,
        category: "OS Vulnerability",
        description: "OpenSSL package has known CVE",
        severityHint: "MEDIUM",
      },
    ];
  }
}
