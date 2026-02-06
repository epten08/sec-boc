import { existsSync, readFileSync } from "fs";
import { parse } from "yaml";
import { dirname, resolve } from "path";

export function fileExists(path: string): boolean {
  return existsSync(path);
}

export function readYaml<T>(path: string): T {
  const content = readFileSync(path, "utf-8");
  return parse(content) as T;
}

export function resolveRelativeTo(basePath: string, relativePath: string): string {
  const baseDir = dirname(basePath);
  return resolve(baseDir, relativePath);
}

export function getProjectRoot(): string {
  return process.cwd();
}
