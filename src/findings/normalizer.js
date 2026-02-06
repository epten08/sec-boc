"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.normalizeFindings = normalizeFindings;
var uuid_1 = require("uuid");
function normalizeFindings(raw) {
    return raw.map(function (r) {
        var _a;
        return ({
            id: (0, uuid_1.v4)(),
            title: r.description,
            category: r.category,
            severity: mapSeverity(r.severityHint),
            endpoint: r.endpoint,
            evidence: (_a = r.evidence) !== null && _a !== void 0 ? _a : "No evidence provided",
            exploitability: 0.5,
            confidence: 0.7,
            sources: [r.source],
        });
    });
}
function mapSeverity(hint) {
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
