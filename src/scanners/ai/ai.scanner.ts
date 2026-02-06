import { Scanner } from "../scanner";
import { ExecutionContext } from "../../orchestrator/context";
import { RawFinding } from "../../findings/raw.finding";
import { TestGenerator } from "../../ai/test.generator";
import { TestExecutor } from "../../ai/executor";
import { TestEvaluator } from "../../ai/evaluator";
import { AIConfig } from "../../ai/adversary";
import { logger } from "../../core/logger";

export interface AIScannnerConfig {
  provider: "ollama" | "openai" | "anthropic";
  model: string;
  baseUrl?: string;
  apiKey?: string;
  maxTests?: number;
}

export class AIScanner implements Scanner {
  name = "AI Security Tester";
  category = "ai" as const;

  private config: AIScannnerConfig;

  constructor(config: AIScannnerConfig) {
    this.config = config;
  }

  async run(ctx: ExecutionContext): Promise<RawFinding[]> {
    logger.scanner(this.name, "start", "Generating and executing security tests");

    const aiConfig: AIConfig = {
      provider: this.config.provider,
      model: this.config.model,
      baseUrl: this.config.baseUrl,
      apiKey: this.config.apiKey,
    };

    // Check if AI is available
    const generator = new TestGenerator(ctx, aiConfig);
    const isAvailable = await generator.isAvailable();

    if (!isAvailable) {
      logger.warn(`AI provider ${this.config.provider} not available, using fallback tests`);
    }

    try {
      // Generate test cases
      const maxTests = this.config.maxTests || 10;
      const testCases = await generator.generateTestCases(maxTests);
      logger.debug(`Generated ${testCases.length} test cases`);

      if (testCases.length === 0) {
        logger.warn("No test cases generated");
        return [];
      }

      // Execute tests
      const executor = new TestExecutor(ctx);
      const results = await executor.execute(testCases);
      logger.debug(`Executed ${results.length} tests, ${results.filter((r) => r.isVulnerable).length} potential vulnerabilities`);

      // Evaluate results
      const evaluator = new TestEvaluator(ctx, isAvailable ? aiConfig : undefined);
      const findings = await evaluator.evaluate(results);

      logger.scanner(this.name, "done", `Found ${findings.length} issues`);
      return findings;
    } catch (err) {
      logger.scanner(this.name, "error", (err as Error).message);
      return [];
    }
  }
}
