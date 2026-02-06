"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var orchestrator_1 = require("./src/orchestrator/orchestrator");
var trivy_static_1 = require("./src/scanners/static/trivy.static");
var trivy_image_1 = require("./src/scanners/container/trivy.image");
var zap_api_1 = require("./src/scanners/dynamic/zap.api");
var orchestrator = new orchestrator_1.Orchestrator([
    new trivy_static_1.TrivyStaticScanner(),
    new trivy_image_1.TrivyImageScanner(),
    new zap_api_1.ZapApiScanner(),
]);
var findings = await orchestrator.run({
    targetUrl: "http://localhost:3000",
    config: { failOnSeverity: "HIGH" },
});
console.log(findings);
