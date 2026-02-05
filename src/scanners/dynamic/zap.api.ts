import { Scanner } from "../scanner";
import { ExecutionContext } from "../../orchestrator/context";
import { RawFinding } from "../../findings/raw.finding";

export class ZapApiScanner implements Scanner {
  name = "OWASP ZAP API";
  category = "dynamic" as const;

  async run(ctx: ExecutionContext): Promise<RawFinding[]> {
    return [
      {
        source: this.name,
        category: "Broken Access Control",
        description: "Unauthorized access to admin endpoint",
        endpoint: `${ctx.targetUrl}/admin/users`,
        severityHint: "CRITICAL",
      },
    ];
  }
}
