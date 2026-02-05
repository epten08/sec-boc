import { OpenAPIObject } from "openapi3-ts/oas30";

export interface AuthContext {
  type: "jwt" | "apikey" | "session";
  token?: string;
  apiKey?: string;
}

export interface SecurityConfig {
  failOnSeverity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface ExecutionContext {
  targetUrl: string;
  openApi?: OpenAPIObject;
  auth?: AuthContext;
  config: SecurityConfig;
}
