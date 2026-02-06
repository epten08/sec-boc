import { readFileSync, existsSync } from "fs";
import { parse } from "yaml";
import { ConfigError } from "./errors";
import { logger } from "./logger";
import { Severity } from "../findings/finding";

export interface EndpointConfig {
  path: string;
  method?: string;
  description?: string;
  params?: Record<string, string>;
  body?: Record<string, unknown>;
}

export interface TargetConfig {
  dockerCompose?: string;
  baseUrl?: string;
  openApiSpec?: string;
  healthEndpoint?: string;
  healthTimeout?: number;
  endpoints?: EndpointConfig[];
}

export interface AuthConfig {
  type: "jwt" | "apikey" | "session" | "none";
  token?: string;
  apiKey?: string;
  headerName?: string;
}

export interface ScannersConfig {
  static: {
    enabled: boolean;
    trivy?: {
      severityThreshold?: Severity;
      ignoreUnfixed?: boolean;
    };
  };
  container: {
    enabled: boolean;
    images?: string[];
    trivy?: {
      severityThreshold?: Severity;
      ignoreUnfixed?: boolean;
    };
  };
  dynamic: {
    enabled: boolean;
    zap?: {
      apiScanType?: "api" | "full";
      maxDuration?: number;
    };
  };
  ai: {
    enabled: boolean;
    provider?: "ollama" | "openai" | "anthropic";
    model?: string;
    baseUrl?: string;
    maxTests?: number;
  };
}

export interface ReportingConfig {
  outputDir: string;
  formats: ("markdown" | "json")[];
  includeEvidence: boolean;
}

export interface SecurityBotConfig {
  version: string;
  target: TargetConfig;
  auth?: AuthConfig;
  scanners: ScannersConfig;
  thresholds: {
    failOn: Severity;
    warnOn: Severity;
  };
  reporting: ReportingConfig;
}

const DEFAULT_CONFIG: SecurityBotConfig = {
  version: "1.0",
  target: {},
  scanners: {
    static: { enabled: true },
    container: { enabled: true },
    dynamic: { enabled: true },
    ai: { enabled: false },
  },
  thresholds: {
    failOn: "HIGH",
    warnOn: "MEDIUM",
  },
  reporting: {
    outputDir: "./security-reports",
    formats: ["markdown", "json"],
    includeEvidence: true,
  },
};

export function loadConfig(configPath?: string): SecurityBotConfig {
  const path = configPath || findConfigFile();

  if (!path) {
    logger.warn("No config file found, using defaults");
    return DEFAULT_CONFIG;
  }

  logger.info(`Loading config from ${path}`);

  try {
    const content = readFileSync(path, "utf-8");
    const parsed = parse(content) as Partial<SecurityBotConfig>;
    return mergeConfig(DEFAULT_CONFIG, parsed);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ENOENT") {
      throw new ConfigError(`Config file not found: ${path}`);
    }
    throw new ConfigError(`Failed to parse config: ${(err as Error).message}`, err as Error);
  }
}

function findConfigFile(): string | null {
  const candidates = [
    "security.config.yml",
    "security.config.yaml",
    ".security.yml",
    ".security.yaml",
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      return candidate;
    }
  }
  return null;
}

function mergeConfig(
  defaults: SecurityBotConfig,
  overrides: Partial<SecurityBotConfig>
): SecurityBotConfig {
  return {
    version: overrides.version ?? defaults.version,
    target: { ...defaults.target, ...overrides.target },
    auth: overrides.auth ?? defaults.auth,
    scanners: {
      static: { ...defaults.scanners.static, ...overrides.scanners?.static },
      container: { ...defaults.scanners.container, ...overrides.scanners?.container },
      dynamic: { ...defaults.scanners.dynamic, ...overrides.scanners?.dynamic },
      ai: { ...defaults.scanners.ai, ...overrides.scanners?.ai },
    },
    thresholds: { ...defaults.thresholds, ...overrides.thresholds },
    reporting: { ...defaults.reporting, ...overrides.reporting },
  };
}

export function validateConfig(config: SecurityBotConfig): void {
  const errors: string[] = [];

  if (!config.target.dockerCompose && !config.target.baseUrl) {
    errors.push("Either target.dockerCompose or target.baseUrl must be specified");
  }

  if (config.scanners.ai.enabled) {
    if (!config.scanners.ai.provider) {
      errors.push("AI provider must be specified when AI scanning is enabled");
    }
  }

  if (config.auth?.type === "jwt" && !config.auth.token) {
    errors.push("JWT token must be provided when auth type is jwt");
  }

  if (config.auth?.type === "apikey" && !config.auth.apiKey) {
    errors.push("API key must be provided when auth type is apikey");
  }

  if (errors.length > 0) {
    throw new ConfigError(`Invalid configuration:\n  - ${errors.join("\n  - ")}`);
  }
}
