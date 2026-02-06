import { OpenAPIObject } from "openapi3-ts/oas30";

export interface AuthContext {
  type: "jwt" | "apikey" | "session" | "none";
  token?: string;
  apiKey?: string;
  headerName?: string;
}

export interface SecurityConfig {
  failOnSeverity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
}

export interface EnvironmentContext {
  baseUrl: string;
  images: string[];
  services: string[];
  managedByUs: boolean;
}

export interface EndpointConfig {
  path: string;
  method?: string;
  description?: string;
  params?: Record<string, string>;
  body?: Record<string, unknown>;
}

export interface ExecutionContext {
  targetUrl: string;
  environment: EnvironmentContext;
  openApi?: OpenAPIObject;
  auth?: AuthContext;
  config: SecurityConfig;
  endpoints?: EndpointConfig[];
}
