/**
 * Programmatic API.
 *
 *   import { audit, ASI_RULES } from "agentaudit";
 *   const result = audit({ root: "./src" });
 */

export { scan, DEFAULT_INCLUDE, DEFAULT_EXCLUDE } from "./scanner.js";
export { ASI_RULES } from "./rules/asi.js";
export { LLM_RULES, EU_AI_ACT_RULES } from "./rules/llm.js";
export {
  terminalReport,
  markdownReport,
  jsonReport,
  sarifReport,
  sortFindings,
  countBySeverity,
} from "./report.js";
export type {
  Rule,
  Probe,
  Finding,
  Severity,
  ScanOptions,
  ScanResult,
} from "./types.js";

import { scan, DEFAULT_INCLUDE, DEFAULT_EXCLUDE } from "./scanner.js";
import { ASI_RULES } from "./rules/asi.js";
import { LLM_RULES, EU_AI_ACT_RULES } from "./rules/llm.js";
import type { Rule, ScanResult } from "./types.js";

export interface AuditOptions {
  root: string;
  rules?: Rule[];
  include?: RegExp;
  exclude?: RegExp;
  maxFileBytes?: number;
}

export function audit(options: AuditOptions): ScanResult {
  return scan({
    root: options.root,
    include: options.include ?? DEFAULT_INCLUDE,
    exclude: options.exclude ?? DEFAULT_EXCLUDE,
    maxFileBytes: options.maxFileBytes ?? 512_000,
    rules: options.rules ?? [...ASI_RULES, ...LLM_RULES, ...EU_AI_ACT_RULES],
  });
}
