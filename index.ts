import { Orchestrator } from "./src/orchestrator/orchestrator";
import { TrivyStaticScanner } from "./src/scanners/static/trivy.static";
import { TrivyImageScanner } from "./src/scanners/container/trivy.image";
import { ZapApiScanner } from "./src/scanners/dynamic/zap.api";

const orchestrator = new Orchestrator([
  new TrivyStaticScanner(),
  new TrivyImageScanner(),
  new ZapApiScanner(),
]);

const findings = await orchestrator.run({
  targetUrl: "http://localhost:3000",
  config: { failOnSeverity: "HIGH" },
});

console.log(findings);
