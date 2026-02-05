import { Scanner } from "../scanner";
import { ExecutionContext } from "../../orchestrator/context";
import { RawFinding } from "../../findings/raw.finding";

export class TrivyStaticScanner implements Scanner {
  name = "Trivy Static";
  category = "static" as const;

  async run(_: ExecutionContext): Promise<RawFinding[]> {
    return [
      {
        source: this.name,
        category: "Dependency Vulnerability",
        description: "Lodash version vulnerable to prototype pollution",
        severityHint: "HIGH",
        evidence: "lodash@4.17.19",
      },
    ];
  }
}
